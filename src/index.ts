import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { sign, verify } from 'hono/jwt'

type Bindings = {
  DB: D1Database
  TELEPATHY_ROOM: DurableObjectNamespace
  JWT_SECRET?: string          // บังคับตั้งผ่าน `wrangler secret put JWT_SECRET`
  ALLOWED_ORIGINS?: string     // เช่น "https://sitluangpu.pages.dev,https://yourdomain.com" (เว้นว่าง = อนุญาตทุกโดเมน)
  SITE_URL?: string            // ใช้สร้าง sitemap เช่น "https://sitluangpu.pages.dev"
  TURNSTILE_SECRET?: string    // ถ้าตั้งไว้ จะใช้ Cloudflare Turnstile แทน bot check แบบเดิม
}

const app = new Hono<{ Bindings: Bindings }>()

// ==========================================
// ค่าคงที่
// ==========================================
const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7      // อายุ token 7 วัน (เดิม 30 วัน)
const MIN_PASSWORD_LENGTH = 8
const MAX_PASSWORD_LENGTH = 128
const PBKDF2_ITERATIONS = 100000                // เพดานที่ Cloudflare Workers รองรับ
const PBKDF2_PREFIX = 'p1:'                     // ขึ้นต้น salt เพื่อบอกว่าเป็นรหัสแบบ PBKDF2
const REQUIRE_AUTH_NOTIFICATIONS = true         // ต้องส่ง Authorization header เมื่อดึงแจ้งเตือน
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/

// ==========================================
// CORS
// ==========================================
app.use('/api/*', cors({
  origin: (origin, c) => {
    const allowed = String((c.env as any)?.ALLOWED_ORIGINS || '').split(',').map((s: string) => s.trim()).filter(Boolean)
    if (allowed.length === 0) return '*'
    return allowed.includes(origin) ? origin : ''
  },
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}))

// ==========================================
// สร้างตาราง/ดัชนีเสริมอัตโนมัติ (ทำครั้งเดียวต่อ isolate)
// ==========================================
let schemaReady: Promise<void> | null = null
function ensureSchema(db: D1Database) {
  if (!schemaReady) {
    schemaReady = (async () => {
      const statements = [
        `CREATE TABLE IF NOT EXISTS post_likes (post_id TEXT NOT NULL, username TEXT NOT NULL, PRIMARY KEY (post_id, username))`,
        `CREATE TABLE IF NOT EXISTS comment_likes (comment_id TEXT NOT NULL, username TEXT NOT NULL, PRIMARY KEY (comment_id, username))`,
        `CREATE TABLE IF NOT EXISTS rate_limits (k TEXT PRIMARY KEY, count INTEGER NOT NULL, window_start INTEGER NOT NULL, lock_until INTEGER NOT NULL DEFAULT 0)`,
        `CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id)`,
        `CREATE INDEX IF NOT EXISTS idx_notifications_recipient ON notifications(recipient, id)`,
        `CREATE INDEX IF NOT EXISTS idx_bookmarks_user ON bookmarks(username, post_id)`,
      ]
      for (const s of statements) {
        try { await db.prepare(s).run() } catch (e) {}
      }
    })()
  }
  return schemaReady
}

app.use('/api/*', async (c, next) => {
  await ensureSchema(c.env.DB)
  await next()
})

// ==========================================
// ฟังก์ชันเสริมทั่วไป
// ==========================================
async function broadcastEvent(env: Bindings, eventData: any) {
  try {
    const id = env.TELEPATHY_ROOM.idFromName('global-telepathy-room')
    const stub = env.TELEPATHY_ROOM.get(id)
    await stub.fetch(new Request('http://internal/broadcast', {
      method: 'POST',
      body: JSON.stringify(eventData)
    }))
  } catch (err) {
    console.error('Broadcast error:', err)
  }
}

function toHex(buf: ArrayBuffer) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
}

function safeEqual(a: string, b: string) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

// รหัสผ่านแบบเดิม (SHA-256 + salt) เก็บไว้เพื่อให้ผู้ใช้เก่าล็อกอินได้ แล้วอัปเกรดอัตโนมัติ
async function hashPasswordLegacy(password: string, salt: string) {
  const data = new TextEncoder().encode(password + salt)
  return toHex(await crypto.subtle.digest('SHA-256', data))
}

async function hashPasswordPbkdf2(password: string, salt: string) {
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: PBKDF2_ITERATIONS },
    key, 256
  )
  return toHex(bits)
}

async function createPasswordRecord(password: string) {
  const salt = PBKDF2_PREFIX + crypto.randomUUID()
  return { salt, hash: await hashPasswordPbkdf2(password, salt) }
}

async function verifyPassword(password: any, user: any): Promise<{ ok: boolean, needsUpgrade: boolean }> {
  if (typeof password !== 'string' || !user?.password_hash || !user?.salt) return { ok: false, needsUpgrade: false }
  const salt = String(user.salt)
  if (salt.startsWith(PBKDF2_PREFIX)) {
    const computed = await hashPasswordPbkdf2(password, salt)
    return { ok: safeEqual(computed, String(user.password_hash)), needsUpgrade: false }
  }
  const computed = await hashPasswordLegacy(password, salt)
  const ok = safeEqual(computed, String(user.password_hash))
  return { ok, needsUpgrade: ok }
}

async function upgradePasswordHash(db: D1Database, username: string, password: string) {
  try {
    const rec = await createPasswordRecord(password)
    await db.prepare("UPDATE users SET password_hash = ?, salt = ? WHERE username = ?").bind(rec.hash, rec.salt, username).run()
  } catch (e) {}
}

// ทำความสะอาดข้อความ: ตัดแท็กอันตราย, event handler และ URL แบบ javascript: (เกราะชั้นแรก — ฝั่งหน้าเว็บยัง escape ซ้ำเสมอ)
function sanitize(text: any) {
  if (!text) return ''
  return String(text)
    .replace(/<\s*(script|iframe|object|embed|style|link|meta|base|form)\b[\s\S]*?(?:<\s*\/\s*\1\s*>|$)/gi, '')
    .replace(/<\s*\/?\s*(?:script|iframe|object|embed|style|link|meta|base|form)\b[^>]*>/gi, '')
    .replace(/<[^<>]*>/g, (tag: string) => tag
      .replace(/[\s\/]on\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '')
      .replace(/\b(href|src|action|formaction|xlink:href)\s*=\s*(["']?)\s*(?:javascript|vbscript|data)\s*:[^"'\s>]*/gi, '$1=$2#'))
}

function cleanStr(v: any, max: number) {
  return typeof v === 'string' ? v.trim().slice(0, max) : ''
}

function isValidId(v: any) {
  return (typeof v === 'string' || typeof v === 'number') && ID_RE.test(String(v))
}

function newId() {
  return Date.now().toString() + Math.floor(Math.random() * 10000).toString().padStart(4, '0')
}

function xmlEscape(s: string) {
  return String(s).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[ch] as string))
}

function isSafeUrl(u: string) {
  if (!u) return true
  return !/^\s*(javascript|data|vbscript)\s*:/i.test(u)
}

function isSafeCssValue(v: string) {
  return /^[#\w\s().,%\-]{1,120}$/.test(v) && !/url\s*\(|expression|javascript|@import/i.test(v)
}

// แปลงเวลา Cloudflare (UTC) ให้เป็นเวลาไทย (+7)
function getThaiTimeStr() {
  const thaiMonths = ['ม.ค.', 'ก.พ.', 'มี.ค.', 'เม.ย.', 'พ.ค.', 'มิ.ย.', 'ก.ค.', 'ส.ค.', 'ก.ย.', 'ต.ค.', 'พ.ย.', 'ธ.ค.']
  const now = new Date(Date.now() + 7 * 60 * 60 * 1000)
  return now.getUTCDate() + ' ' + thaiMonths[now.getUTCMonth()] + ' ' + (now.getUTCFullYear() + 543) + ' | ' + String(now.getUTCHours()).padStart(2, '0') + ':' + String(now.getUTCMinutes()).padStart(2, '0') + ' น.'
}

// ==========================================
// JWT & Authentication (ตรวจ role จากฐานข้อมูลทุกครั้ง)
// ==========================================
async function generateToken(payload: { username: string; role: string; rank_name: string }, secret: string) {
  return await sign({
    ...payload,
    exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS
  }, secret, 'HS256')
}

async function getAuthenticatedUser(c: any): Promise<{ user: any, error: string | null }> {
  try {
    const secret = c.env?.JWT_SECRET
    if (!secret) return { user: null, error: 'Server Misconfigured' }

    const authHeader = c.req.raw.headers.get('Authorization') || c.req.raw.headers.get('authorization')
    if (!authHeader) return { user: null, error: 'Header Missing' }

    const token = authHeader.replace(/^Bearer\s+/i, '').replace(/['"]/g, '').trim()
    if (!token || token === 'undefined' || token === 'null') return { user: null, error: 'Token Empty' }

    const decoded: any = await verify(token, secret, 'HS256')

    // role / rank ใช้ค่าล่าสุดจาก DB เสมอ — ถ้าถูกลบหรือลดสิทธิ์ token เก่าจะไม่มีผลทันที
    const row: any = await c.env.DB.prepare("SELECT username, role, rank_name FROM users WHERE username = ?").bind(decoded.username).first()
    if (!row) return { user: null, error: 'User Not Found' }

    return { user: { username: row.username, role: String(row.role ?? '5'), rank_name: row.rank_name }, error: null }
  } catch (e: any) {
    return { user: null, error: 'Token Invalid' }
  }
}

async function requireAdmin(c: any): Promise<any | null> {
  const { user } = await getAuthenticatedUser(c)
  return user && String(user.role) === '1' ? user : null
}

// ==========================================
// ระบบคำนวณยศและแต้มบุญ (Karma)
// ==========================================
function calculateRank(karma: number, currentRole: string, currentRankName: string) {
  const standardRoles = ['2', '3', '4', '5']
  if (currentRole === '1' || currentRankName === 'ตัวละคร' || (!standardRoles.includes(String(currentRole)) && currentRole !== '')) {
    return { role: currentRole, rank_name: currentRankName, nextRankMsg: 'ยศพิเศษแต่งตั้ง / ข้อยกเว้น' }
  }
  if (karma >= 51) return { role: '2', rank_name: 'ตติยภูมิ', nextRankMsg: 'ตบะขั้นสูงสุดของศิษย์ทั่วไป' }
  if (karma >= 21) return { role: '3', rank_name: 'ทุติยภูมิ', nextRankMsg: `อีก ${51 - karma} แต้มบุญ จะเลื่อนเป็น ตติยภูมิ` }
  if (karma >= 11) return { role: '4', rank_name: 'ปฐมภูมิ', nextRankMsg: `อีก ${21 - karma} แต้มบุญ จะเลื่อนเป็น ทุติยภูมิ` }
  return { role: '5', rank_name: 'เด็กวัด', nextRankMsg: `อีก ${11 - karma} แต้มบุญ จะเลื่อนเป็น ปฐมภูมิ` }
}

// เพิ่มแต้มแบบ atomic (ไม่อ่านแล้วเขียนทับ) แล้วค่อยคำนวณยศ
async function addKarma(db: D1Database, username: string, amount: number) {
  try {
    if (!username || username.includes('ผู้ไม่ประสงค์ออกนาม')) return
    const before: any = await db.prepare("SELECT role, rank_name FROM users WHERE username = ?").bind(username).first()
    if (!before || String(before.role) === '1' || before.rank_name === 'ตัวละคร') return

    await db.prepare("UPDATE users SET karma = COALESCE(karma, 0) + ? WHERE username = ?").bind(amount, username).run()
    const user: any = await db.prepare("SELECT karma, role, rank_name FROM users WHERE username = ?").bind(username).first()
    if (!user) return
    const rankInfo = calculateRank(user.karma || 0, String(user.role), user.rank_name)
    if (String(rankInfo.role) !== String(user.role) || rankInfo.rank_name !== user.rank_name) {
      await db.prepare("UPDATE users SET role = ?, rank_name = ? WHERE username = ?").bind(rankInfo.role, rankInfo.rank_name, username).run()
    }
  } catch (e) {}
}

// ==========================================
// Rate Limit แบบเก็บใน D1 (ใช้ได้จริงข้ามทุก isolate)
// ==========================================
async function rlCheck(db: D1Database, key: string): Promise<{ allowed: boolean, waitTimeStr?: string }> {
  try {
    const row: any = await db.prepare("SELECT lock_until FROM rate_limits WHERE k = ?").bind(key).first()
    if (!row) return { allowed: true }
    const now = Date.now()
    if (row.lock_until > now) {
      return { allowed: false, waitTimeStr: `${Math.ceil((row.lock_until - now) / 60000)} นาที` }
    }
    if (row.lock_until > 0) await db.prepare("DELETE FROM rate_limits WHERE k = ?").bind(key).run()
  } catch (e) {}
  return { allowed: true }
}

async function rlRecord(db: D1Database, key: string, max: number, windowMs: number, lockMs: number) {
  try {
    const now = Date.now()
    const row: any = await db.prepare("SELECT count, window_start FROM rate_limits WHERE k = ?").bind(key).first()
    if (!row || now - row.window_start > windowMs) {
      await db.prepare("INSERT OR REPLACE INTO rate_limits (k, count, window_start, lock_until) VALUES (?, 1, ?, 0)").bind(key, now).run()
      return
    }
    const count = row.count + 1
    await db.prepare("UPDATE rate_limits SET count = ?, lock_until = ? WHERE k = ?").bind(count, count >= max ? now + lockMs : 0, key).run()
  } catch (e) {}
}

async function rlReset(db: D1Database, key: string) {
  try { await db.prepare("DELETE FROM rate_limits WHERE k = ?").bind(key).run() } catch (e) {}
}

const LOGIN_MAX = 5, LOGIN_WINDOW = 15 * 60 * 1000, LOGIN_LOCK = 15 * 60 * 1000
const REGISTER_MAX = 5, REGISTER_WINDOW = 10 * 60 * 1000, REGISTER_LOCK = 15 * 60 * 1000
const REPORT_MAX = 10, REPORT_WINDOW = 10 * 60 * 1000, REPORT_LOCK = 10 * 60 * 1000

function getIp(c: any) {
  return c.req.header('cf-connecting-ip') || 'unknown'
}

// ==========================================
// ตรวจสอบว่าเป็นมนุษย์ (Turnstile ถ้าตั้งค่าไว้ ไม่เช่นนั้นใช้ bot check เดิม)
// ==========================================
const BOT_CHECK_ANSWERS = new Set(['สัตยาสาบาน', 'ศิษย์หลวงปู่', 'ลานเสวนา', '2', '3', '7', 'คน'])

function normalizeAnswer(str: string) {
  return String(str || '').trim().replace(/\s+/g, '')
}

function isValidBotCheckAnswer(answer: string) {
  return BOT_CHECK_ANSWERS.has(normalizeAnswer(answer))
}

async function verifyTurnstile(secret: string, token: any, ip: string) {
  if (typeof token !== 'string' || !token) return false
  try {
    const form = new FormData()
    form.append('secret', secret)
    form.append('response', token)
    if (ip !== 'unknown') form.append('remoteip', ip)
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form })
    const data: any = await res.json()
    return !!data.success
  } catch (e) { return false }
}

async function isHuman(c: any, body: any, ip: string) {
  const secret = c.env?.TURNSTILE_SECRET
  if (secret) return await verifyTurnstile(secret, body.turnstile_token, ip)
  return isValidBotCheckAnswer(body.bot_check_answer)
}

// ==========================================
// กฎของชื่อผู้ใช้
// ==========================================
const RESERVED_WORDS = ['แอดมิน', 'แอทมิน', 'ผู้ดูแล', 'ทีมงาน', 'เจ้าหน้าที่', 'ระบบ', 'ผู้คุมกฎ', 'ปรมัตถ์', 'สตาฟ', 'เว็บมาสเตอร์', 'ศิษย์หลวงปู่', 'เจ้าสำนัก', 'ผู้บริหาร', 'สต๊าฟ', 'ซัพพอร์ต', 'ส่วนกลาง', 'แอด']

function validateUsername(username: any): string | null {
  if (typeof username !== 'string' || !/^[\u0E00-\u0E7F]{2,30}$/.test(username)) {
    return 'นามแฝงอนุญาตเฉพาะ "อักขระภาษาไทย" ความยาว 2-30 ตัว และห้ามเว้นวรรคเด็ดขาด!'
  }
  if (RESERVED_WORDS.some(word => username.includes(word))) {
    return 'นามแฝงนี้มีคำสงวนของสำนักประทับอยู่ ไม่อนุญาตให้ใช้งาน!'
  }
  return null
}

function validatePassword(password: any): string | null {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
    return `รหัสผ่านต้องยาวอย่างน้อย ${MIN_PASSWORD_LENGTH} ตัวอักษร`
  }
  if (password.length > MAX_PASSWORD_LENGTH) return 'รหัสผ่านยาวเกินไป'
  return null
}

// ==========================================
// ระบบแจ้งเตือน (ตรวจว่าผู้รับมีอยู่จริง + กันแจ้งซ้ำคนเดิม)
// ==========================================
async function notify(env: Bindings, recipient: string, actor: string, actionType: string, postRef: string, notified: Set<string>, timeStr: string) {
  if (!recipient || recipient === actor || notified.has(recipient)) return
  try {
    const exists = await env.DB.prepare("SELECT 1 AS ok FROM users WHERE username = ?").bind(recipient).first()
    if (!exists) return
    notified.add(recipient)
    await env.DB.prepare(
      "INSERT INTO notifications (id, recipient, actor, action_type, post_id, is_read, timestamp) VALUES (?, ?, ?, ?, ?, 0, ?)"
    ).bind(newId(), recipient, actor, actionType, postRef, timeStr).run()
    await broadcastEvent(env, { type: 'NEW_NOTIFICATION', targetUser: recipient })
  } catch (e) {}
}

const MENTION_REGEX = /@([\u0E00-\u0E7Fa-zA-Z0-9_-]+)/g
function extractMentions(text: string) {
  return [...new Set([...text.matchAll(MENTION_REGEX)].map(m => m[1]))].slice(0, 10)
}

// ==========================================
// === AUTH & USERS ROUTES ===
// ==========================================

const LOGIN_FAIL_MSG = 'นามแฝงหรือรหัสผ่านไม่ถูกต้อง'
const ADMIN_FAIL_MSG = 'นามหรือรหัสผ่านอาคมไม่ถูกต้อง หรือท่านไม่ใช่ "ผู้คุมกฎ"'

app.post('/api/login', async (c) => {
  const ip = getIp(c)
  const key = `login:${ip}`
  const rl = await rlCheck(c.env.DB, key)
  if (!rl.allowed) return c.json({ success: false, error: `ระงับชั่วคราวจากการเข้าระบบผิดพลาดเกินขีดจำกัด โปรดรออีก ${rl.waitTimeStr}` }, 429)

  try {
    const secret = c.env.JWT_SECRET
    if (!secret) return c.json({ success: false, error: 'เซิร์ฟเวอร์ตั้งค่าไม่สมบูรณ์' }, 500)

    const body: any = await c.req.json().catch(() => ({}))
    const { username, password } = body
    if (typeof username !== 'string' || typeof password !== 'string') {
      return c.json({ success: false, error: LOGIN_FAIL_MSG }, 400)
    }

    const user: any = await c.env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first()
    if (!user) {
      await hashPasswordPbkdf2(password, PBKDF2_PREFIX + 'dummy') // เท่ากันเรื่องเวลา ไม่บอกว่าชื่อมีอยู่หรือไม่
      if (ip !== 'unknown') await rlRecord(c.env.DB, key, LOGIN_MAX, LOGIN_WINDOW, LOGIN_LOCK)
      return c.json({ success: false, error: LOGIN_FAIL_MSG }, 400)
    }

    const check = await verifyPassword(password, user)
    if (!check.ok) {
      if (ip !== 'unknown') await rlRecord(c.env.DB, key, LOGIN_MAX, LOGIN_WINDOW, LOGIN_LOCK)
      return c.json({ success: false, error: LOGIN_FAIL_MSG }, 400)
    }

    await rlReset(c.env.DB, key)
    if (check.needsUpgrade) await upgradePasswordHash(c.env.DB, user.username, password)
    try { await c.env.DB.prepare("UPDATE users SET last_login = ? WHERE username = ?").bind(Date.now(), user.username).run() } catch (e) {}

    const token = await generateToken({ username: user.username, role: String(user.role || '5'), rank_name: user.rank_name || 'เด็กวัด' }, secret)
    const rankInfo = calculateRank(user.karma || 0, String(user.role), user.rank_name)

    return c.json({ success: true, token, username: user.username, role: user.role, rank_name: user.rank_name, karma: user.karma || 0, nextRankMsg: rankInfo.nextRankMsg })
  } catch (err: any) {
    return c.json({ success: false, error: 'เกิดข้อผิดพลาดในการตรวจสอบตัวตน' }, 500)
  }
})

app.post('/api/admin/login', async (c) => {
  const ip = getIp(c)
  const key = `login:${ip}`
  const rl = await rlCheck(c.env.DB, key)
  if (!rl.allowed) return c.json({ success: false, error: `ระบบป้องกันทำงาน! อาณาเขตถูกปิดกั้น โปรดรออีก ${rl.waitTimeStr}` }, 429)

  try {
    const secret = c.env.JWT_SECRET
    if (!secret) return c.json({ success: false, error: 'เซิร์ฟเวอร์ตั้งค่าไม่สมบูรณ์' }, 500)

    const body: any = await c.req.json().catch(() => ({}))
    const { username, password } = body
    if (typeof username !== 'string' || typeof password !== 'string') {
      return c.json({ success: false, error: ADMIN_FAIL_MSG }, 400)
    }

    const user: any = await c.env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first()
    let ok = false
    let needsUpgrade = false
    if (user) {
      const check = await verifyPassword(password, user)
      ok = check.ok && String(user.role) === '1'
      needsUpgrade = check.ok && check.needsUpgrade
    } else {
      await hashPasswordPbkdf2(password, PBKDF2_PREFIX + 'dummy')
    }

    if (!ok) {
      if (ip !== 'unknown') await rlRecord(c.env.DB, key, LOGIN_MAX, LOGIN_WINDOW, LOGIN_LOCK)
      return c.json({ success: false, error: ADMIN_FAIL_MSG }, 400)
    }

    await rlReset(c.env.DB, key)
    if (needsUpgrade) await upgradePasswordHash(c.env.DB, user.username, password)
    try { await c.env.DB.prepare("UPDATE users SET last_login = ? WHERE username = ?").bind(Date.now(), user.username).run() } catch (e) {}

    const token = await generateToken({ username: user.username, role: '1', rank_name: user.rank_name || 'ปรมัตถ์' }, secret)
    return c.json({ success: true, token, username: user.username, rank_name: user.rank_name || 'เด็กวัด' })
  } catch (err) { return c.json({ success: false, error: 'เกิดข้อผิดพลาดที่แก่นเซิร์ฟเวอร์' }, 500) }
})

app.get('/api/me', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ authenticated: false, error: authResult.error }, 401)

  const user: any = await c.env.DB.prepare("SELECT username, role, rank_name, karma, last_login FROM users WHERE username = ?").bind(authResult.user.username).first()
  if (!user) return c.json({ authenticated: false }, 404)
  const rankInfo = calculateRank(user.karma || 0, String(user.role), user.rank_name)
  return c.json({ authenticated: true, user: { ...user, nextRankMsg: rankInfo.nextRankMsg } })
})

app.get('/api/users', async (c) => {
  const { results } = await c.env.DB.prepare("SELECT username, role, rank_name, karma, last_login, sort_order FROM users ORDER BY sort_order ASC, username ASC").all()
  const usersWithKarmaInfo = results.map((u: any) => {
    const rankInfo = calculateRank(u.karma || 0, String(u.role), u.rank_name)
    return { ...u, nextRankMsg: rankInfo.nextRankMsg }
  })
  return c.json(usersWithKarmaInfo)
})

app.post('/api/users', async (c) => {
  const ip = getIp(c)
  const body: any = await c.req.json().catch(() => null)
  if (!body || typeof body !== 'object') return c.json({ success: false, message: 'ข้อมูลไม่ถูกต้อง' }, 400)
  const { username, password, role, rank_name } = body

  const adminUser = await requireAdmin(c)
  const isAdmin = !!adminUser

  if (!isAdmin) {
    const key = `register:${ip}`
    const rl = ip === 'unknown' ? { allowed: true } as any : await rlCheck(c.env.DB, key)
    if (!rl.allowed) return c.json({ success: false, message: `มีการสมัครถี่เกินไปจาก IP นี้ โปรดรออีก ${rl.waitTimeStr}` }, 429)

    const human = await isHuman(c, body, ip)
    if (ip !== 'unknown') await rlRecord(c.env.DB, key, REGISTER_MAX, REGISTER_WINDOW, REGISTER_LOCK)
    if (!human) return c.json({ success: false, message: 'โดนสกัดกั้น! คำตอบยืนยันตัวตนไม่ถูกต้อง' }, 403)
  }

  const nameErr = validateUsername(username)
  if (nameErr) return c.json({ success: false, message: nameErr }, 400)
  const pwErr = validatePassword(password)
  if (pwErr) return c.json({ success: false, message: pwErr }, 400)

  // ผู้สมัครทั่วไปได้ยศเริ่มต้นเท่านั้น — กำหนดเองได้เฉพาะแอดมิน
  const safeRole = isAdmin && typeof role !== 'undefined' && /^[\w-]{1,40}$/.test(String(role)) ? String(role) : '5'
  const safeRank = isAdmin ? (cleanStr(rank_name, 40) || 'เด็กวัด') : 'เด็กวัด'

  const secret = c.env.JWT_SECRET
  if (!secret) return c.json({ success: false, message: 'เซิร์ฟเวอร์ตั้งค่าไม่สมบูรณ์' }, 500)

  try {
    const rec = await createPasswordRecord(password)
    await c.env.DB.prepare(
      "INSERT INTO users (username, password_hash, salt, role, rank_name, last_login, karma, sort_order) VALUES (?, ?, ?, ?, ?, NULL, 0, 0)"
    ).bind(username, rec.hash, rec.salt, safeRole, safeRank).run()

    const token = await generateToken({ username, role: safeRole, rank_name: safeRank }, secret)
    return c.json({ success: true, token, username })
  } catch (e: any) {
    return c.json({ success: false, message: 'ไม่สามารถสร้างบัญชีได้ นามแฝงนี้อาจถูกใช้ไปแล้ว' }, 400)
  }
})

app.put('/api/users', async (c) => {
  const admin = await requireAdmin(c)
  if (!admin) return c.json({ success: false, error: 'Forbidden' }, 403)

  const body: any = await c.req.json().catch(() => null)
  if (!body || typeof body !== 'object') return c.json({ success: false, message: 'ข้อมูลไม่ถูกต้อง' }, 400)
  const { username, oldUsername, password, role, rank_name, last_login, karma } = body
  const targetName = typeof oldUsername === 'string' && oldUsername ? oldUsername : username

  const nameErr = validateUsername(username)
  if (nameErr) return c.json({ success: false, message: nameErr }, 400)

  const hasPassword = typeof password === 'string' && password.length > 0
  if (hasPassword) {
    const pwErr = validatePassword(password)
    if (pwErr) return c.json({ success: false, message: pwErr }, 400)
  }

  const safeRole = /^[\w-]{1,40}$/.test(String(role ?? '5')) ? String(role ?? '5') : '5'
  const safeRank = cleanStr(rank_name, 40) || 'เด็กวัด'
  // ถ้าไม่ได้ส่ง karma มา ให้คงค่าเดิม (เดิมถูกรีเซ็ตเป็น 0)
  const safeKarma = typeof karma === 'number' && isFinite(karma) ? Math.max(0, Math.floor(karma)) : null

  if (targetName === admin.username && safeRole !== '1') {
    return c.json({ success: false, message: 'ไม่สามารถลดสิทธิ์ของตนเองได้' }, 400)
  }

  try {
    const existing: any = await c.env.DB.prepare("SELECT username FROM users WHERE username = ?").bind(targetName).first()
    if (!existing) return c.json({ success: false, message: 'ไม่พบผู้ใช้ที่ต้องการแก้ไข' }, 404)

    const renamed = username !== targetName
    if (renamed) {
      const taken: any = await c.env.DB.prepare("SELECT username FROM users WHERE username = ?").bind(username).first()
      if (taken) return c.json({ success: false, message: 'นามแฝงใหม่ถูกใช้ไปแล้ว' }, 409)
    }

    const db = c.env.DB
    const statements: D1PreparedStatement[] = []
    const lastLogin = last_login || null

    if (hasPassword) {
      const rec = await createPasswordRecord(password)
      statements.push(db.prepare(
        "UPDATE users SET username = ?, password_hash = ?, salt = ?, role = ?, rank_name = ?, last_login = COALESCE(?, last_login), karma = COALESCE(?, karma) WHERE username = ?"
      ).bind(username, rec.hash, rec.salt, safeRole, safeRank, lastLogin, safeKarma, targetName))
    } else {
      statements.push(db.prepare(
        "UPDATE users SET username = ?, role = ?, rank_name = ?, last_login = COALESCE(?, last_login), karma = COALESCE(?, karma) WHERE username = ?"
      ).bind(username, safeRole, safeRank, lastLogin, safeKarma, targetName))
    }

    // เปลี่ยนชื่อแล้วต้องย้ายข้อมูลที่อ้างอิงชื่อเดิมตามไปด้วย (กันข้อมูลกำพร้า)
    if (renamed) {
      statements.push(db.prepare("UPDATE posts SET author = ? WHERE author = ?").bind(username, targetName))
      statements.push(db.prepare("UPDATE comments SET author = ? WHERE author = ?").bind(username, targetName))
      statements.push(db.prepare("UPDATE bookmarks SET id = ? || '_' || post_id, username = ? WHERE username = ?").bind(username, username, targetName))
      statements.push(db.prepare("UPDATE notifications SET recipient = ? WHERE recipient = ?").bind(username, targetName))
      statements.push(db.prepare("UPDATE notifications SET actor = ? WHERE actor = ?").bind(username, targetName))
      statements.push(db.prepare("UPDATE reports SET reporter = ? WHERE reporter = ?").bind(username, targetName))
      statements.push(db.prepare("UPDATE post_likes SET username = ? WHERE username = ?").bind(username, targetName))
      statements.push(db.prepare("UPDATE comment_likes SET username = ? WHERE username = ?").bind(username, targetName))
    }

    await db.batch(statements)
    return c.json({ success: true })
  } catch (e) { return c.json({ success: false, message: 'ไม่สามารถอัปเดตข้อมูลผู้ใช้ได้' }, 400) }
})

app.put('/api/users/reorder', async (c) => {
  const admin = await requireAdmin(c)
  if (!admin) return c.json({ success: false, error: 'Forbidden' }, 403)

  try {
    const { orderedUsernames } = await c.req.json()
    if (!Array.isArray(orderedUsernames) || orderedUsernames.length > 1000 || orderedUsernames.some((u: any) => typeof u !== 'string')) {
      return c.json({ success: false, error: 'Invalid data format' }, 400)
    }

    const stmt = c.env.DB.prepare("UPDATE users SET sort_order = ? WHERE username = ?")
    await c.env.DB.batch(orderedUsernames.map((name: string, i: number) => stmt.bind(i, name)))
    return c.json({ success: true })
  } catch (e: any) {
    return c.json({ success: false, error: 'บันทึกลำดับไม่สำเร็จ' }, 500)
  }
})

app.delete('/api/users/:username', async (c) => {
  const admin = await requireAdmin(c)
  if (!admin) return c.json({ success: false, error: 'Forbidden' }, 403)

  const username = c.req.param('username')
  if (username === admin.username) return c.json({ success: false, error: 'ไม่สามารถลบบัญชีของตนเองได้' }, 400)

  await c.env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run()
  return c.json({ success: true })
})

// ==========================================
// === POSTS & COMMENTS ROUTES ===
// ==========================================

app.get('/api/posts', async (c) => {
  // รองรับ ?limit=&offset= (ไม่ส่งมา = ส่งทั้งหมดเหมือนเดิม)
  const limitQ = parseInt(c.req.query('limit') || '', 10)
  const offsetQ = parseInt(c.req.query('offset') || '', 10)
  if (limitQ > 0) {
    const limit = Math.min(limitQ, 200)
    const offset = offsetQ > 0 ? offsetQ : 0
    const { results } = await c.env.DB.prepare("SELECT * FROM posts ORDER BY id DESC LIMIT ? OFFSET ?").bind(limit, offset).all()
    return c.json(results)
  }
  const { results } = await c.env.DB.prepare("SELECT * FROM posts ORDER BY id DESC").all()
  return c.json(results)
})

app.post('/api/posts', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)
  const author = authResult.user.username
  const isAdmin = String(authResult.user.role) === '1'

  const body: any = await c.req.json().catch(() => null)
  if (!body || typeof body !== 'object') return c.json({ success: false, error: 'ข้อมูลไม่ถูกต้อง' }, 400)

  const title = cleanStr(body.title, 200)
  const category = cleanStr(String(body.category ?? ''), 50)
  const safeContent = sanitize(typeof body.content === 'string' ? body.content.slice(0, 50000) : '')
  if (!title || !safeContent.trim()) return c.json({ success: false, error: 'กรุณากรอกหัวข้อและเนื้อหา' }, 400)

  const postId = isValidId(body.id) ? String(body.id) : newId()
  const now = Date.now()

  if (!isAdmin) {
    const user: any = await c.env.DB.prepare("SELECT last_post_time FROM users WHERE username = ?").bind(author).first()
    const lastPostTime = user?.last_post_time || 0
    if (now - lastPostTime < 30000) {
      const timeLeft = Math.ceil((30000 - (now - lastPostTime)) / 1000)
      return c.json({ success: false, error: `ท่านร่ายเวทมนตร์ถี่เกินไป โปรดพักหายใจอีก ${timeLeft} วินาที` }, 429)
    }
  }

  // เฉพาะแอดมินที่ปักหมุดได้
  const isPinned = isAdmin && (body.pinned === true || body.pinned === 1 || body.pinned === '1') ? 1 : 0
  const timeStr = getThaiTimeStr()

  try {
    await c.env.DB.prepare(
      "INSERT INTO posts (id, category, title, content, author, timestamp, pinned) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).bind(postId, category, title, safeContent, author, timeStr, isPinned).run()
  } catch (e) {
    return c.json({ success: false, error: 'ไม่สามารถบันทึกกระทู้ได้ (รหัสกระทู้อาจซ้ำ)' }, 409)
  }

  await c.env.DB.prepare("UPDATE users SET last_post_time = ? WHERE username = ?").bind(now, author).run()
  await addKarma(c.env.DB, author, 2)

  try {
    const notified = new Set<string>()
    for (const mentioned of extractMentions(`${title} ${safeContent}`)) {
      await notify(c.env, mentioned, author, 'mention', postId, notified, timeStr)
    }
  } catch (notiErr) {}

  return c.json({ success: true, id: postId })
})

app.put('/api/posts', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)
  const authUser = authResult.user
  const isAdmin = String(authUser.role) === '1'

  const body: any = await c.req.json().catch(() => null)
  if (!body || !isValidId(body.id)) return c.json({ success: false, error: 'ข้อมูลไม่ถูกต้อง' }, 400)

  const post: any = await c.env.DB.prepare("SELECT author, pinned FROM posts WHERE id = ?").bind(String(body.id)).first()
  if (!post) return c.json({ success: false, error: 'ไม่พบศิลาจารึกที่ต้องการแก้ไข' }, 404)

  if (!isAdmin && authUser.username !== post.author) {
    return c.json({ success: false, error: 'Forbidden: ท่านไม่มีสิทธิ์แก้ไขจารึกของผู้อื่น' }, 403)
  }

  const title = cleanStr(body.title, 200)
  const category = cleanStr(String(body.category ?? ''), 50)
  const safeContent = sanitize(typeof body.content === 'string' ? body.content.slice(0, 50000) : '')
  if (!title || !safeContent.trim()) return c.json({ success: false, error: 'กรุณากรอกหัวข้อและเนื้อหา' }, 400)

  // ผู้ใช้ทั่วไปแก้สถานะปักหมุดไม่ได้ — คงค่าเดิมไว้
  const isPinned = isAdmin
    ? ((body.pinned === true || body.pinned === 1 || body.pinned === '1') ? 1 : 0)
    : (post.pinned ? 1 : 0)

  try {
    await c.env.DB.prepare(
      "UPDATE posts SET category = ?, title = ?, content = ?, pinned = ? WHERE id = ?"
    ).bind(category, title, safeContent, isPinned, String(body.id)).run()
    return c.json({ success: true })
  } catch (e: any) { return c.json({ success: false, error: 'แก้ไขกระทู้ไม่สำเร็จ' }, 500) }
})

app.get('/api/posts/:id', async (c) => {
  const id = c.req.param('id')
  // ?noview=1 ใช้สำหรับ middleware/บอต เพื่อไม่ให้นับยอดวิวซ้ำ
  if (c.req.query('noview') !== '1') {
    try { await c.env.DB.prepare("UPDATE posts SET views = COALESCE(views, 0) + 1 WHERE id = ?").bind(id).run() } catch (e) {}
  }
  const post = await c.env.DB.prepare("SELECT * FROM posts WHERE id = ?").bind(id).first()
  if (!post) return c.json({ error: 'Not found' }, 404)
  return c.json(post)
})

app.delete('/api/posts/:id', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)
  const authUser = authResult.user

  const id = c.req.param('id')
  const post: any = await c.env.DB.prepare("SELECT author FROM posts WHERE id = ?").bind(id).first()
  if (!post) return c.json({ success: false, error: 'ไม่พบศิลาจารึก' }, 404)

  if (String(authUser.role) !== '1' && authUser.username !== post.author) {
    return c.json({ success: false, error: 'Forbidden' }, 403)
  }

  const db = c.env.DB
  await db.batch([
    db.prepare("DELETE FROM comment_likes WHERE comment_id IN (SELECT id FROM comments WHERE post_id = ?)").bind(id),
    db.prepare("DELETE FROM comments WHERE post_id = ?").bind(id),
    db.prepare("DELETE FROM post_likes WHERE post_id = ?").bind(id),
    db.prepare("DELETE FROM bookmarks WHERE CAST(post_id AS TEXT) = ?").bind(id),
    // ลบเฉพาะแจ้งเตือนของกระทู้นี้ (เดิมใช้ LIKE 'id%' ทำให้กระทู้ id ขึ้นต้นเหมือนกันโดนลบไปด้วย)
    db.prepare("DELETE FROM notifications WHERE post_id = ? OR substr(post_id, 1, ?) = ?").bind(id, id.length + 1, `${id}#`),
    db.prepare("DELETE FROM posts WHERE id = ?").bind(id),
  ])
  return c.json({ success: true })
})

app.post('/api/posts/:postId/like', async (c) => {
  const postId = c.req.param('postId')
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)
  const actor = authResult.user.username

  try {
    const post: any = await c.env.DB.prepare("SELECT id, author, likes FROM posts WHERE id = ?").bind(postId).first()
    if (!post) return c.json({ success: false, error: 'ไม่พบศิลาจารึก' }, 404)

    // 1 คน 1 ไลก์ต่อกระทู้
    const ins = await c.env.DB.prepare("INSERT OR IGNORE INTO post_likes (post_id, username) VALUES (?, ?)").bind(String(postId), actor).run()
    const added = ((ins as any).meta?.changes ?? 0) > 0

    if (added) {
      await c.env.DB.prepare("UPDATE posts SET likes = COALESCE(likes, 0) + 1 WHERE id = ?").bind(postId).run()
      if (post.author && post.author !== actor) {
        await notify(c.env, post.author, actor, 'like_post', String(postId), new Set<string>(), getThaiTimeStr())
        await addKarma(c.env.DB, post.author, 1)
      }
    }

    const fresh: any = await c.env.DB.prepare("SELECT likes FROM posts WHERE id = ?").bind(postId).first()
    const likes = fresh?.likes || 0
    if (added) await broadcastEvent(c.env, { type: 'LIKE_UPDATE', targetId: postId, newLikes: likes, isComment: false })

    return c.json({ success: true, likes, alreadyLiked: !added })
  } catch (e: any) { return c.json({ success: false, error: 'ไม่สามารถกดไลก์ได้' }, 500) }
})

app.get('/api/comments', async (c) => {
  const { results } = await c.env.DB.prepare("SELECT * FROM comments ORDER BY id ASC").all()
  return c.json(results)
})

app.get('/api/posts/:postId/comments', async (c) => {
  const postId = c.req.param('postId')
  const { results } = await c.env.DB.prepare("SELECT * FROM comments WHERE post_id = ? ORDER BY id ASC").bind(postId).all()
  return c.json(results)
})

app.post('/api/comments', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)
  const author = authResult.user.username
  const isAdmin = String(authResult.user.role) === '1'

  const body: any = await c.req.json().catch(() => null)
  if (!body || typeof body !== 'object' || !isValidId(body.postId)) return c.json({ success: false, error: 'ข้อมูลไม่ถูกต้อง' }, 400)
  const postId = String(body.postId)

  const safeContent = sanitize(typeof body.content === 'string' ? body.content.slice(0, 5000) : '')
  if (!safeContent.trim()) return c.json({ success: false, error: 'กรุณากรอกข้อความ' }, 400)

  const post: any = await c.env.DB.prepare("SELECT author FROM posts WHERE id = ?").bind(postId).first()
  if (!post) return c.json({ success: false, error: 'ไม่พบศิลาจารึก' }, 404)

  const now = Date.now()
  if (!isAdmin) {
    const user: any = await c.env.DB.prepare("SELECT last_comment_time FROM users WHERE username = ?").bind(author).first()
    const lastCommentTime = user?.last_comment_time || 0
    if (now - lastCommentTime < 15000) {
      const timeLeft = Math.ceil((15000 - (now - lastCommentTime)) / 1000)
      return c.json({ success: false, error: `ท่านส่งกระแสจิตถี่เกินไป โปรดพักอีก ${timeLeft} วินาที` }, 429)
    }
  }

  const commentId = isValidId(body.id) ? String(body.id) : newId()
  const timeStr = getThaiTimeStr()

  try {
    await c.env.DB.batch([
      c.env.DB.prepare("INSERT INTO comments (id, post_id, author, content, timestamp) VALUES (?, ?, ?, ?, ?)")
        .bind(commentId, postId, author, safeContent, timeStr),
      c.env.DB.prepare("UPDATE posts SET replies = COALESCE(replies, 0) + 1 WHERE id = ?").bind(postId),
      c.env.DB.prepare("UPDATE users SET last_comment_time = ? WHERE username = ?").bind(now, author),
    ])
  } catch (e) {
    return c.json({ success: false, error: 'ไม่สามารถบันทึกความเห็นได้ (รหัสอาจซ้ำ)' }, 409)
  }
  await addKarma(c.env.DB, author, 1)

  try {
    const targetRef = `${postId}#comment-${commentId}`
    const notified = new Set<string>()

    // 1) คนที่ถูกตอบกลับ  2) คนที่ถูกแท็ก  3) เจ้าของกระทู้ — คนเดียวกันได้แจ้งเตือนครั้งเดียว
    const replyMatch = safeContent.match(/\[AUTHOR:([^\]]+)\]/)
    if (replyMatch && replyMatch[1]) {
      await notify(c.env, replyMatch[1], author, 'reply', targetRef, notified, timeStr)
    }
    for (const mentioned of extractMentions(safeContent)) {
      await notify(c.env, mentioned, author, 'mention', targetRef, notified, timeStr)
    }
    if (post.author) {
      await notify(c.env, post.author, author, 'comment', targetRef, notified, timeStr)
    }

    await broadcastEvent(c.env, { type: 'NEW_COMMENT', postId })
  } catch (notiErr) {}

  return c.json({ success: true, id: commentId })
})

app.delete('/api/comments/:id', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)
  const authUser = authResult.user

  const id = c.req.param('id')
  const comment: any = await c.env.DB.prepare("SELECT post_id, author FROM comments WHERE id = ?").bind(id).first()
  if (!comment) return c.json({ success: false, error: 'ไม่พบความเห็น' }, 404)

  if (String(authUser.role) !== '1' && authUser.username !== comment.author) {
    return c.json({ success: false, error: 'Forbidden' }, 403)
  }

  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE posts SET replies = MAX(0, COALESCE(replies, 0) - 1) WHERE id = ?").bind(comment.post_id),
    c.env.DB.prepare("DELETE FROM comment_likes WHERE comment_id = ?").bind(id),
    c.env.DB.prepare("DELETE FROM comments WHERE id = ?").bind(id),
  ])
  return c.json({ success: true })
})

app.post('/api/comments/:commentId/like', async (c) => {
  const commentId = c.req.param('commentId')
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)
  const actor = authResult.user.username

  try {
    const comment: any = await c.env.DB.prepare("SELECT id, post_id, author FROM comments WHERE id = ?").bind(commentId).first()
    if (!comment) return c.json({ success: false, error: 'ไม่พบความเห็น' }, 404)

    const ins = await c.env.DB.prepare("INSERT OR IGNORE INTO comment_likes (comment_id, username) VALUES (?, ?)").bind(String(commentId), actor).run()
    const added = ((ins as any).meta?.changes ?? 0) > 0

    if (added) {
      await c.env.DB.prepare("UPDATE comments SET likes = COALESCE(likes, 0) + 1 WHERE id = ?").bind(commentId).run()
      if (comment.author && comment.author !== actor) {
        await notify(c.env, comment.author, actor, 'like_comment', `${comment.post_id}#comment-${commentId}`, new Set<string>(), getThaiTimeStr())
        await addKarma(c.env.DB, comment.author, 1)
      }
    }

    const fresh: any = await c.env.DB.prepare("SELECT likes FROM comments WHERE id = ?").bind(commentId).first()
    const likes = fresh?.likes || 0
    if (added) await broadcastEvent(c.env, { type: 'LIKE_UPDATE', targetId: commentId, newLikes: likes, isComment: true })

    return c.json({ success: true, likes, alreadyLiked: !added })
  } catch (e: any) { return c.json({ success: false, error: 'ไม่สามารถกดไลก์ได้' }, 500) }
})

// ==========================================
// === OTHERS (ROLES, REPORTS, BOOKMARKS, CMS) ===
// ==========================================

app.get('/api/roles', async (c) => {
  try {
    const { results } = await c.env.DB.prepare("SELECT * FROM roles ORDER BY level ASC, rank_name ASC").all()
    return c.json(results || [])
  } catch (e) { return c.json([]) }
})

app.post('/api/roles', async (c) => {
  if (!(await requireAdmin(c))) return c.json({ success: false, error: 'Forbidden' }, 403)

  const body: any = await c.req.json().catch(() => ({}))
  const rankName = cleanStr(body.rank_name, 40)
  const bg = cleanStr(body.bg_color, 120)
  const text = cleanStr(body.text_color, 120)
  const border = cleanStr(body.border_color, 120)
  // ค่าสีถูกนำไปใส่ใน style="..." ฝั่งหน้าเว็บ จึงต้องจำกัดรูปแบบ
  if (!rankName || !isSafeCssValue(bg) || !isSafeCssValue(text) || (border && !isSafeCssValue(border))) {
    return c.json({ success: false, error: 'ข้อมูลยศหรือรหัสสีไม่ถูกต้อง' }, 400)
  }
  const level = Math.min(99, Math.max(1, parseInt(body.level, 10) || 5))

  try {
    const id = `dynamic_${crypto.randomUUID().substring(0, 8)}`
    await c.env.DB.prepare(
      "INSERT INTO roles (id, rank_name, bg_color, text_color, border_color, level) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(id, rankName, bg, text, border, level).run()
    return c.json({ success: true, id })
  } catch (e: any) { return c.json({ success: false, error: 'สร้างยศไม่สำเร็จ' }, 500) }
})

app.delete('/api/roles/:id', async (c) => {
  if (!(await requireAdmin(c))) return c.json({ success: false, error: 'Forbidden' }, 403)

  const id = c.req.param('id')
  try {
    await c.env.DB.prepare("DELETE FROM roles WHERE id = ?").bind(id).run()
    return c.json({ success: true })
  } catch (e: any) { return c.json({ success: false, error: 'ลบยศไม่สำเร็จ' }, 500) }
})

app.get('/api/reports', async (c) => {
  if (!(await requireAdmin(c))) return c.json([], 403)

  try {
    const { results } = await c.env.DB.prepare("SELECT * FROM reports ORDER BY id DESC").all()
    return c.json(results || [])
  } catch (e) { return c.json([]) }
})

app.post('/api/reports', async (c) => {
  // รับรายงานแบบไม่ล็อกอินได้ (เพื่อให้หน้าเว็บเดิมใช้งานต่อได้) แต่จำกัดอัตราต่อ IP และตรวจรูปแบบข้อมูลทั้งหมด
  const ip = getIp(c)
  const key = `report:${ip}`
  if (ip !== 'unknown') {
    const rl = await rlCheck(c.env.DB, key)
    if (!rl.allowed) return c.json({ success: false, error: `ส่งรายงานถี่เกินไป โปรดรออีก ${rl.waitTimeStr}` }, 429)
    await rlRecord(c.env.DB, key, REPORT_MAX, REPORT_WINDOW, REPORT_LOCK)
  }

  const body: any = await c.req.json().catch(() => null)
  if (!body || typeof body !== 'object') return c.json({ success: false, error: 'ข้อมูลไม่ถูกต้อง' }, 400)

  const targetType = body.target_type === 'post' || body.target_type === 'comment' ? body.target_type : null
  const targetId = String(body.target_id ?? '')
  if (!targetType || !/^[\w#-]{1,80}$/.test(targetId)) return c.json({ success: false, error: 'ข้อมูลรายงานไม่ถูกต้อง' }, 400)

  const reason = cleanStr(body.reason, 500)
  if (!reason) return c.json({ success: false, error: 'กรุณาระบุเหตุผล' }, 400)

  const { user } = await getAuthenticatedUser(c)
  const reporter = user ? user.username : (cleanStr(body.reporter, 40) || 'ผู้ไม่ประสงค์ออกนาม')
  const id = isValidId(body.id) ? String(body.id) : newId()

  try {
    await c.env.DB.prepare(
      "INSERT INTO reports (id, target_type, target_id, reporter, reason, timestamp) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(id, targetType, targetId, reporter, reason, getThaiTimeStr()).run()
    return c.json({ success: true })
  } catch (error: any) { return c.json({ success: false, error: 'ส่งรายงานไม่สำเร็จ' }, 500) }
})

app.delete('/api/reports/:id', async (c) => {
  if (!(await requireAdmin(c))) return c.json({ success: false, error: 'Forbidden' }, 403)

  const id = c.req.param('id')
  try {
    await c.env.DB.prepare("DELETE FROM reports WHERE id = ?").bind(id).run()
    return c.json({ success: true })
  } catch (error: any) { return c.json({ success: false, error: 'ลบรายงานไม่สำเร็จ' }, 500) }
})

app.get('/api/bookmarks', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json([], 200)

  try {
    const { results } = await c.env.DB.prepare(
      "SELECT b.post_id, p.title, b.timestamp FROM bookmarks b JOIN posts p ON CAST(b.post_id AS TEXT) = CAST(p.id AS TEXT) WHERE b.username = ? ORDER BY b.timestamp DESC"
    ).bind(authResult.user.username).all()
    return c.json(results || [])
  } catch (e: any) { return c.json([], 200) }
})

app.post('/api/bookmarks', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)

  const body: any = await c.req.json().catch(() => ({}))
  const postId = body.postId || body.post_id
  if (!isValidId(postId)) return c.json({ success: false, error: 'ไม่พบรหัสจารึก' }, 400)
  try {
    const id = `${authResult.user.username}_${postId}`
    const timeStr = new Date().toISOString()
    await c.env.DB.prepare(
      "INSERT OR REPLACE INTO bookmarks (id, username, post_id, timestamp) VALUES (?, ?, ?, ?)"
    ).bind(id, authResult.user.username, String(postId), timeStr).run()
    return c.json({ success: true })
  } catch (e: any) { return c.json({ success: false, error: 'บันทึกไม่สำเร็จ' }, 500) }
})

app.delete('/api/bookmarks/:postId', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)

  const postId = c.req.param('postId')
  try {
    await c.env.DB.prepare(
      "DELETE FROM bookmarks WHERE username = ? AND CAST(post_id AS TEXT) = CAST(? AS TEXT)"
    ).bind(authResult.user.username, String(postId)).run()
    return c.json({ success: true })
  } catch (e: any) { return c.json({ success: false, error: 'ลบไม่สำเร็จ' }, 500) }
})

app.get('/api/cms', async (c) => {
  const cms = await c.env.DB.prepare("SELECT * FROM cms WHERE id = 1").first()
  return c.json(cms || {})
})

app.post('/api/cms', async (c) => {
  if (!(await requireAdmin(c))) return c.json({ success: false, error: 'Forbidden' }, 403)

  const body: any = await c.req.json().catch(() => ({}))
  const heroSubtitle = cleanStr(body.heroSubtitle, 300)
  const heroDesc = cleanStr(body.heroDesc, 2000)
  const heroImg = cleanStr(body.heroImg, 1000)
  const heroBtnText = cleanStr(body.heroBtnText, 100)
  const heroBtnUrl = cleanStr(body.heroBtnUrl, 1000)

  // กันลิงก์ javascript:/data: ที่หน้าแรกจะนำไปใส่ href/src
  if (!isSafeUrl(heroImg) || !isSafeUrl(heroBtnUrl)) {
    return c.json({ success: false, error: 'รูปแบบลิงก์ไม่ปลอดภัย' }, 400)
  }

  await c.env.DB.prepare(
    `INSERT INTO cms (id, heroSubtitle, heroDesc, heroImg, heroBtnText, heroBtnUrl)
     VALUES (1, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       heroSubtitle = excluded.heroSubtitle, heroDesc = excluded.heroDesc, heroImg = excluded.heroImg,
       heroBtnText = excluded.heroBtnText, heroBtnUrl = excluded.heroBtnUrl`
  ).bind(heroSubtitle, heroDesc, heroImg, heroBtnText, heroBtnUrl).run()

  return c.json({ success: true })
})

app.get('/api/notifications/:username', async (c) => {
  const username = c.req.param('username')

  if (REQUIRE_AUTH_NOTIFICATIONS) {
    const { user } = await getAuthenticatedUser(c)
    if (!user) return c.json([], 401)
    if (user.username !== username && String(user.role) !== '1') return c.json([], 403)
  }

  try {
    const { results } = await c.env.DB.prepare("SELECT * FROM notifications WHERE recipient = ? ORDER BY id DESC LIMIT 30").bind(username).all()
    return c.json(results || [])
  } catch (e) { return c.json([]) }
})

app.post('/api/notifications', async (c) => {
  return c.json({ success: true, ignored: true })
})

app.put('/api/notifications/:id/read', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: 'Unauthorized' }, 401)

  const id = c.req.param('id')
  try {
    // แก้ได้เฉพาะแจ้งเตือนของตัวเอง (แอดมินแก้ได้ทั้งหมด)
    if (String(authResult.user.role) === '1') {
      await c.env.DB.prepare("UPDATE notifications SET is_read = 1 WHERE id = ?").bind(id).run()
    } else {
      await c.env.DB.prepare("UPDATE notifications SET is_read = 1 WHERE id = ? AND recipient = ?").bind(id, authResult.user.username).run()
    }
    return c.json({ success: true })
  } catch (error: any) { return c.json({ success: false, error: 'อัปเดตไม่สำเร็จ' }, 500) }
})

app.get('/sitemap.xml', async (c) => {
  try {
    const { results } = await c.env.DB.prepare("SELECT id FROM posts ORDER BY id DESC").all()
    const baseUrl = (c.env.SITE_URL || 'https://sitluangpu.pages.dev').replace(/\/+$/, '')
    let xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n`
    xml += `  <url>\n    <loc>${xmlEscape(baseUrl)}/index.html</loc>\n    <priority>1.0</priority>\n  </url>\n`
    xml += `  <url>\n    <loc>${xmlEscape(baseUrl)}/webboard.html</loc>\n    <priority>0.9</priority>\n  </url>\n`
    if (results) {
      results.forEach((post: any) => {
        xml += `  <url>\n    <loc>${xmlEscape(baseUrl)}/post.html?id=${xmlEscape(encodeURIComponent(String(post.id)))}</loc>\n    <priority>0.8</priority>\n  </url>\n`
      })
    }
    xml += `</urlset>`
    c.header('Content-Type', 'application/xml')
    return c.text(xml)
  } catch (e: any) { return c.text('Error generating sitemap', 500) }
})

app.get('/api/ws', async (c) => {
  const upgradeHeader = c.req.header('Upgrade')
  if (upgradeHeader !== 'websocket') return c.text('Expected Upgrade: websocket', 426)
  const id = c.env.TELEPATHY_ROOM.idFromName('global-telepathy-room')
  const stub = c.env.TELEPATHY_ROOM.get(id)
  return stub.fetch(c.req.raw)
})

export default app

// ==========================================
// Durable Object: ห้องกระแสจิต (WebSocket Hibernation)
// - กระจายสัญญาณเฉพาะที่ Backend ส่งมาทาง /broadcast เท่านั้น
// - ข้อความที่ client ส่งเข้ามาจะถูกเพิกเฉย (กันการปลอมแจ้งเตือน/ยอดไลก์)
// ==========================================
export class TelepathyRoom {
  state: DurableObjectState

  constructor(state: DurableObjectState, env: any) {
    this.state = state
  }

  async fetch(request: Request) {
    const url = new URL(request.url)

    if (request.method === 'POST' && url.pathname === '/broadcast') {
      const payload = await request.text()
      for (const ws of this.state.getWebSockets()) {
        try { ws.send(payload) } catch (e) {}
      }
      return new Response('Broadcast Success', { status: 200 })
    }

    if (request.headers.get('Upgrade') !== 'websocket') return new Response('Expected Upgrade: websocket', { status: 426 })

    const webSocketPair = new WebSocketPair()
    const client = webSocketPair[0]
    const server = webSocketPair[1]
    this.state.acceptWebSocket(server)
    return new Response(null, { status: 101, webSocket: client })
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer) {
    // ไม่รับคำสั่งจากฝั่ง client
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean) {
    try { ws.close(1000, 'closing') } catch (e) {}
  }

  async webSocketError(ws: WebSocket, error: unknown) {
    try { ws.close(1011, 'error') } catch (e) {}
  }
}
