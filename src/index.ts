import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { sign, verify } from 'hono/jwt'

type Bindings = {
  DB: D1Database
  TELEPATHY_ROOM: DurableObjectNamespace
  JWT_SECRET?: string
}

const app = new Hono<{ Bindings: Bindings }>()

app.use('/api/*', cors())

// 🌟 กุญแจอาคมสำหรับเข้ารหัส Token (เปลี่ยนหรือตั้งใน wrangler.jsonc ได้)
const DEFAULT_JWT_SECRET = 'sitluangpu_telepathy_secret_token_2026'

async function hashPassword(password: string, salt: string) {
  const encoder = new TextEncoder()
  const data = encoder.encode(password + salt)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

function sanitize(text: string) {
  if (!text) return text;
  return text.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
             .replace(/on\w+="[^"]*"/gi, '')
             .replace(/on\w+='[^']*'/gi, '')
}

// ==========================================
// 🛡️ ฟังก์ชันจัดการ Token ยืนยันตัวตน (JWT)
// ==========================================
async function generateToken(payload: { username: string; role: string; rank_name: string }, secret: string) {
  return await sign({
    ...payload,
    exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 30) // ตรายางมีอายุ 30 วัน
  }, secret)
}

async function getAuthenticatedUser(c: any): Promise<{ username: string; role: string; rank_name: string } | null> {
  const authHeader = c.req.header('Authorization')
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null
  const token = authHeader.substring(7)
  try {
    const secret = c.env.JWT_SECRET || DEFAULT_JWT_SECRET
    const payload = await verify(token, secret)
    return payload as any
  } catch (e) {
    return null
  }
}

// ==========================================
// 🛠️ ฟังก์ชันคำนวณยศ (Auto-Rank System)
// ==========================================
function calculateRank(karma: number, currentRole: string, currentRankName: string) {
  if (currentRole === '1' || currentRankName === 'ตัวละคร') {
    return { role: currentRole, rank_name: currentRankName, nextRankMsg: 'ยศพิเศษเฉพาะกิจ' };
  }
  
  if (karma >= 51) return { role: '2', rank_name: 'ตติยภูมิ', nextRankMsg: 'ตบะขั้นสูงสุดของศิษย์ทั่วไป' };
  if (karma >= 21) return { role: '3', rank_name: 'ทุติยภูมิ', nextRankMsg: `อีก ${51 - karma} แต้มบุญ จะเลื่อนเป็น ตติยภูมิ` };
  if (karma >= 11) return { role: '4', rank_name: 'ปฐมภูมิ', nextRankMsg: `อีก ${21 - karma} แต้มบุญ จะเลื่อนเป็น ทุติยภูมิ` };
  return { role: '5', rank_name: 'เด็กวัด', nextRankMsg: `อีก ${11 - karma} แต้มบุญ จะเลื่อนเป็น ปฐมภูมิ` };
}

async function addKarma(db: D1Database, username: string, amount: number) {
  try {
    if (!username || username.includes('ผู้ไม่ประสงค์ออกนาม')) return;
    
    const user: any = await db.prepare("SELECT * FROM users WHERE username = ?").bind(username).first()
    if (!user || String(user.role) === '1' || user.rank_name === 'ตัวละคร') return;

    const newKarma = (user.karma || 0) + amount;
    const rankInfo = calculateRank(newKarma, String(user.role), user.rank_name);

    await db.prepare(
      "UPDATE users SET karma = ?, role = ?, rank_name = ? WHERE username = ?"
    ).bind(newKarma, rankInfo.role, rankInfo.rank_name, username).run()
  } catch (e) {
    console.error("Error adding karma:", e)
  }
}

// ==========================================
// 🛠️ เครื่องมือเสกฐานข้อมูล (Magic Fix DB)
// ==========================================
app.get('/api/fix-db', async (c) => {
  let logs = []
  const queries = [
    "ALTER TABLE posts ADD COLUMN likes INTEGER DEFAULT 0;",
    "ALTER TABLE posts ADD COLUMN views INTEGER DEFAULT 0;",
    "ALTER TABLE posts ADD COLUMN pinned INTEGER DEFAULT 0;",
    "ALTER TABLE comments ADD COLUMN likes INTEGER DEFAULT 0;",
    "ALTER TABLE users ADD COLUMN last_login INTEGER;",
    "ALTER TABLE users ADD COLUMN karma INTEGER DEFAULT 0;",
    `CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY,
        recipient TEXT NOT NULL,
        actor TEXT NOT NULL,
        action_type TEXT NOT NULL,
        post_id TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        timestamp TEXT NOT NULL
    );`,
    `CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        reporter TEXT NOT NULL,
        reason TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        status TEXT DEFAULT 'pending'
    );`
  ]

  for (let q of queries) {
    try {
      await c.env.DB.prepare(q).run()
      logs.push(`✅ สำเร็จ: ${q.split(' ')[0]} ${q.split(' ')[1]} ${q.split(' ')[2] || ''}`)
    } catch (e: any) {
      logs.push(`⚠️ ข้าม (มีอยู่แล้วหรือขัดข้อง): ${e.message}`)
    }
  }
  return c.json({ message: "อัปเกรดฐานข้อมูลเรียบร้อยแล้ว!", logs })
})

// ==========================================
// 🚨 ระบบแจ้งเบาะแส (Report System) 
// ==========================================
app.get('/api/reports', async (c) => {
  try {
    const { results } = await c.env.DB.prepare("SELECT * FROM reports ORDER BY id DESC").all()
    return c.json(results || [])
  } catch (e) { return c.json([]) }
})

app.post('/api/reports', async (c) => {
  const body = await c.req.json()
  try {
    await c.env.DB.prepare(
      "INSERT INTO reports (id, target_type, target_id, reporter, reason, timestamp) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(body.id, body.target_type, body.target_id, body.reporter, body.reason, body.timestamp).run()
    return c.json({ success: true })
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500)
  }
})

app.delete('/api/reports/:id', async (c) => {
  const id = c.req.param('id')
  try {
    await c.env.DB.prepare("DELETE FROM reports WHERE id = ?").bind(id).run()
    return c.json({ success: true })
  } catch (error: any) {
    return c.json({ success: false, error: error.message }, 500)
  }
})

// ==========================================
// 🔑 ระบบเข้าสู่ระบบทั่วไป & แอดมิน (Auth & Token)
// ==========================================
app.post('/api/login', async (c) => {
  try {
    const { username, password } = await c.req.json()
    const user: any = await c.env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first()
    if (!user) return c.json({ success: false, error: 'ไม่พบนามแฝงนี้ในระบบ' }, 400)

    let isValid = false
    if (user.password_hash && user.salt) {
      const computedHash = await hashPassword(password, user.salt)
      if (user.password_hash === computedHash) isValid = true
    }
    if (!isValid && user.password === password) isValid = true
    if (!isValid && user.password_hash === password) isValid = true

    if (!isValid) return c.json({ success: false, error: 'รหัสผ่านลับไม่ถูกต้อง' }, 400)

    const now = Date.now()
    try { await c.env.DB.prepare("UPDATE users SET last_login = ? WHERE username = ?").bind(now, user.username).run() } catch(e) {}

    const secret = c.env.JWT_SECRET || DEFAULT_JWT_SECRET
    const token = await generateToken({
      username: user.username,
      role: String(user.role || '5'),
      rank_name: user.rank_name || 'เด็กวัด'
    }, secret)

    const rankInfo = calculateRank(user.karma || 0, String(user.role), user.rank_name)

    return c.json({
      success: true,
      token,
      username: user.username,
      role: user.role,
      rank_name: user.rank_name,
      karma: user.karma || 0,
      nextRankMsg: rankInfo.nextRankMsg
    })
  } catch (err: any) {
    return c.json({ success: false, error: 'เกิดข้อผิดพลาดในการตรวจสอบตัวตน' }, 500)
  }
})

app.post('/api/admin/login', async (c) => {
  try {
    const { username, password } = await c.req.json();
    const user: any = await c.env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
    if (!user) return c.json({ success: false, error: 'ไม่พบนามของท่านในจารึกเมืองนี้' }, 400);
    if (String(user.role) !== '1') return c.json({ success: false, error: 'ตบะบารมีไม่ถึงขั้น ทวารนี้เฉพาะปรมัตถ์เท่านั้น' }, 403);

    let isValid = false;
    if (user.password_hash && user.salt) {
      const computedHash = await hashPassword(password, user.salt);
      if (user.password_hash === computedHash) isValid = true;
    }
    if (!isValid && user.password === password) isValid = true;
    if (!isValid && user.password_hash === password) isValid = true;

    if (!isValid) return c.json({ success: false, error: 'รหัสผ่านอาคมผิดเพี้ยน!' }, 400);

    try { await c.env.DB.prepare("UPDATE users SET last_login = ? WHERE username = ?").bind(Date.now(), user.username).run(); } catch(e) {}

    const secret = c.env.JWT_SECRET || DEFAULT_JWT_SECRET
    const token = await generateToken({
      username: user.username,
      role: '1',
      rank_name: user.rank_name || 'ปรมัตถ์'
    }, secret)

    return c.json({ success: true, token, username: user.username, rank_name: user.rank_name || 'เด็กวัด' });
  } catch (err) {
    return c.json({ success: false, error: 'เกิดข้อผิดพลาดที่แก่นเซิร์ฟเวอร์' }, 500);
  }
});

// ตรวจสอบ Token ของตัวเอง
app.get('/api/me', async (c) => {
  const authUser = await getAuthenticatedUser(c)
  if (!authUser) return c.json({ authenticated: false }, 401)
  const user: any = await c.env.DB.prepare("SELECT username, role, rank_name, karma, last_login FROM users WHERE username = ?").bind(authUser.username).first()
  if (!user) return c.json({ authenticated: false }, 404)
  const rankInfo = calculateRank(user.karma || 0, String(user.role), user.rank_name)
  return c.json({ authenticated: true, user: { ...user, nextRankMsg: rankInfo.nextRankMsg } })
})

// ==========================================
// 🚪 จัดการสมาชิก 
// ==========================================
app.get('/api/users', async (c) => {
  const { results } = await c.env.DB.prepare("SELECT * FROM users").all()
  const usersWithKarmaInfo = results.map((u: any) => {
    const rankInfo = calculateRank(u.karma || 0, String(u.role), u.rank_name);
    return { ...u, nextRankMsg: rankInfo.nextRankMsg }
  })
  return c.json(usersWithKarmaInfo)
})

app.post('/api/users', async (c) => {
  const { username, password, role, rank_name, last_login } = await c.req.json()
  const salt = crypto.randomUUID()
  const hashed = await hashPassword(password, salt)
  try {
    await c.env.DB.prepare(
      "INSERT INTO users (username, password_hash, salt, role, rank_name, password, last_login, karma) VALUES (?, ?, ?, ?, ?, ?, ?, 0)"
    ).bind(username, hashed, salt, role || '5', rank_name || 'เด็กวัด', password, last_login || null).run()
    
    const secret = c.env.JWT_SECRET || DEFAULT_JWT_SECRET
    const token = await generateToken({
      username,
      role: role || '5',
      rank_name: rank_name || 'เด็กวัด'
    }, secret)

    return c.json({ success: true, token, username })
  } catch (e) {
    return c.json({ success: false, message: 'นามแฝงนี้มีผู้ใช้งานแล้ว' }, 400)
  }
})

app.put('/api/users', async (c) => {
  const { username, oldUsername, password, role, rank_name, last_login, karma } = await c.req.json()
  const targetName = oldUsername || username
  const currentKarma = karma || 0
  
  try {
    if (password) {
      const salt = crypto.randomUUID()
      const hashed = await hashPassword(password, salt)
      await c.env.DB.prepare(
        "UPDATE users SET username = ?, password_hash = ?, salt = ?, role = ?, rank_name = ?, password = ?, last_login = COALESCE(?, last_login), karma = COALESCE(?, karma) WHERE username = ?"
      ).bind(username, hashed, salt, role || '5', rank_name || 'เด็กวัด', password, last_login || null, currentKarma, targetName).run()
    } else {
      await c.env.DB.prepare(
        "UPDATE users SET username = ?, role = ?, rank_name = ?, last_login = COALESCE(?, last_login), karma = COALESCE(?, karma) WHERE username = ?"
      ).bind(username, role || '5', rank_name || 'เด็กวัด', last_login || null, currentKarma, targetName).run()
    }
    return c.json({ success: true })
  } catch (e) {
    return c.json({ success: false, message: 'ไม่สามารถอัปเดตข้อมูลผู้ใช้ได้' }, 400)
  }
})

app.delete('/api/users/:username', async (c) => {
  const username = c.req.param('username')
  await c.env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run()
  return c.json({ success: true })
})

// ==========================================
// 📜 จัดการกระทู้และคอมเมนต์ (Posts & Comments)
// ==========================================
app.get('/api/posts', async (c) => {
  const { results } = await c.env.DB.prepare("SELECT * FROM posts ORDER BY id DESC").all()
  return c.json(results)
})

app.post('/api/posts', async (c) => {
  const body = await c.req.json()
  
  // 🌟 ดึงตัวตนจริงจาก Token หากมี เพื่อป้องกันการปลอมนามแฝง
  const authUser = await getAuthenticatedUser(c)
  const author = authUser ? authUser.username : body.author

  if (!author) {
    return c.json({ success: false, error: 'ไม่พบตัวตนผู้สลักจารึก' }, 401)
  }

  const safeContent = sanitize(body.content)
  const isPinned = (body.pinned === true || body.pinned === 1 || body.pinned === '1') ? 1 : 0;
  
  await c.env.DB.prepare(
    "INSERT INTO posts (id, category, title, content, author, timestamp, pinned) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).bind(body.id, body.category, body.title, safeContent, author, body.timestamp, isPinned).run()
  
  // 🌟 ได้แต้มบุญ +2 จากการตั้งกระทู้
  await addKarma(c.env.DB, author, 2);

  return c.json({ success: true })
})

app.put('/api/posts', async (c) => {
  const body = await c.req.json()
  const safeContent = sanitize(body.content || '')
  const isPinned = (body.pinned === true || body.pinned === 1 || body.pinned === '1') ? 1 : 0;

  try {
    await c.env.DB.prepare(
      "UPDATE posts SET category = ?, title = ?, content = ?, author = ?, pinned = ? WHERE id = ?"
    ).bind(body.category, body.title, safeContent, body.author, isPinned, body.id).run()
    return c.json({ success: true })
  } catch (e: any) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

app.get('/api/posts/:id', async (c) => {
  const id = c.req.param('id')
  try { await c.env.DB.prepare("UPDATE posts SET views = COALESCE(views, 0) + 1 WHERE id = ?").bind(id).run() } catch (e) {}
  const post = await c.env.DB.prepare("SELECT * FROM posts WHERE id = ?").bind(id).first()
  return c.json(post)
})

app.delete('/api/posts/:id', async (c) => {
  const id = c.req.param('id')
  await c.env.DB.prepare("DELETE FROM posts WHERE id = ?").bind(id).run()
  await c.env.DB.prepare("DELETE FROM comments WHERE post_id = ?").bind(id).run()
  return c.json({ success: true })
})

app.post('/api/posts/:postId/like', async (c) => {
  const postId = c.req.param('postId')
  const body = await c.req.json().catch(() => ({}))
  
  const authUser = await getAuthenticatedUser(c)
  const actor = authUser ? authUser.username : (body.actor || 'วิญญาณเร่ร่อน')

  try {
    await c.env.DB.prepare("UPDATE posts SET likes = COALESCE(likes, 0) + 1 WHERE id = ?").bind(postId).run()
    const post: any = await c.env.DB.prepare("SELECT * FROM posts WHERE id = ?").bind(postId).first()
    
    if (post && post.author && post.author !== actor) {
      const notiId = Date.now().toString()
      const thaiMonths = ['ม.ค.', 'ก.พ.', 'มี.ค.', 'เม.ย.', 'พ.ค.', 'มิ.ย.', 'ก.ค.', 'ส.ค.', 'ก.ย.', 'ต.ค.', 'พ.ย.', 'ธ.ค.']
      const now = new Date()
      const timeStr = now.getDate() + ' ' + thaiMonths[now.getMonth()] + ' ' + (now.getFullYear() + 543) + ' | ' + String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0') + ' น.'
      
      await c.env.DB.prepare(
        "INSERT INTO notifications (id, recipient, actor, action_type, post_id, is_read, timestamp) VALUES (?, ?, ?, 'like_post', ?, 0, ?)"
      ).bind(notiId, post.author, actor, postId, timeStr).run().catch(() => {})

      // 🌟 เจ้าของกระทู้ได้แต้มบุญ +1
      await addKarma(c.env.DB, post.author, 1);
    }

    return c.json({ success: true, likes: post?.likes || 0 })
  } catch (e: any) {
    return c.json({ success: false, error: e.message }, 500)
  }
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
  const body = await c.req.json()
  
  // 🌟 ดึงตัวตนจริงจาก Token หากมี เพื่อป้องกันการปลอมนามแฝง
  const authUser = await getAuthenticatedUser(c)
  const author = authUser ? authUser.username : body.author

  if (!author) {
    return c.json({ success: false, error: 'ไม่พบตัวตนผู้สลักความเห็น' }, 401)
  }

  const safeContent = sanitize(body.content)
  await c.env.DB.prepare(
    "INSERT INTO comments (id, post_id, author, content, timestamp) VALUES (?, ?, ?, ?, ?)"
  ).bind(body.id, body.postId, author, safeContent, body.timestamp).run()
  await c.env.DB.prepare("UPDATE posts SET replies = replies + 1 WHERE id = ?").bind(body.postId).run()
  
  // 🌟 ได้แต้มบุญ +1 จากการตอบคอมเมนต์
  await addKarma(c.env.DB, author, 1);

  return c.json({ success: true })
})

app.delete('/api/comments/:id', async (c) => {
  const id = c.req.param('id')
  const comment: any = await c.env.DB.prepare("SELECT post_id FROM comments WHERE id = ?").bind(id).first()
  if (comment) {
    await c.env.DB.prepare("UPDATE posts SET replies = MAX(0, replies - 1) WHERE id = ?").bind(comment.post_id).run()
  }
  await c.env.DB.prepare("DELETE FROM comments WHERE id = ?").bind(id).run()
  return c.json({ success: true })
})

app.post('/api/comments/:commentId/like', async (c) => {
  const commentId = c.req.param('commentId')
  const body = await c.req.json().catch(() => ({}))
  
  const authUser = await getAuthenticatedUser(c)
  const actor = authUser ? authUser.username : (body.actor || 'วิญญาณเร่ร่อน')

  try {
    await c.env.DB.prepare("UPDATE comments SET likes = COALESCE(likes, 0) + 1 WHERE id = ?").bind(commentId).run()
    const comment: any = await c.env.DB.prepare("SELECT * FROM comments WHERE id = ?").bind(commentId).first()
    
    if (comment && comment.author && comment.author !== actor) {
      const notiId = Date.now().toString()
      const thaiMonths = ['ม.ค.', 'ก.พ.', 'มี.ค.', 'เม.ย.', 'พ.ค.', 'มิ.ย.', 'ก.ค.', 'ส.ค.', 'ก.ย.', 'ต.ค.', 'พ.ย.', 'ธ.ค.']
      const now = new Date()
      const timeStr = now.getDate() + ' ' + thaiMonths[now.getMonth()] + ' ' + (now.getFullYear() + 543) + ' | ' + String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0') + ' น.'
      
      await c.env.DB.prepare(
        "INSERT INTO notifications (id, recipient, actor, action_type, post_id, is_read, timestamp) VALUES (?, ?, ?, 'like_comment', ?, 0, ?)"
      ).bind(notiId, comment.author, actor, comment.post_id || comment.postId, timeStr).run().catch(() => {})

      // 🌟 เจ้าของคอมเมนต์ได้แต้มบุญ +1
      await addKarma(c.env.DB, comment.author, 1);
    }

    return c.json({ success: true, likes: comment?.likes || 0 })
  } catch (e: any) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

app.get('/api/cms', async (c) => {
  const cms = await c.env.DB.prepare("SELECT * FROM cms WHERE id = 1").first()
  return c.json(cms || {})
})

app.post('/api/cms', async (c) => {
  const body = await c.req.json()
  const sub = body.heroSubtitle || body.hero_subtitle || ''
  const desc = body.heroDesc || body.hero_desc || ''
  const img = body.heroImg || body.hero_img || ''
  const btnText = body.heroBtnText || body.hero_btn_text || ''
  const btnUrl = body.heroBtnUrl || body.hero_btn_url || ''

  await c.env.DB.prepare(
    "INSERT INTO cms (id, heroSubtitle, heroDesc, heroImg, heroBtnText, heroBtnUrl) VALUES (1, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET heroSubtitle = ?, heroDesc = ?, heroImg = ?, heroBtnText = ?, heroBtnUrl = ?"
  ).bind(
    sub, desc, img, btnText, btnUrl,
    sub, desc, img, btnText, btnUrl
  ).run()
  return c.json({ success: true })
})

// ==========================================
// 🔮 ระบบแจ้งเตือน (Notifications)
// ==========================================
app.get('/api/notifications/:username', async (c) => {
  const username = c.req.param('username')
  try {
    const { results } = await c.env.DB.prepare(
      "SELECT * FROM notifications WHERE recipient = ? ORDER BY id DESC LIMIT 30"
    ).bind(username).all()
    return c.json(results || [])
  } catch (e) {
    return c.json([]) 
  }
})

app.post('/api/notifications', async (c) => {
  const body = await c.req.json()
  const { id, recipient, actor, action_type, post_id, timestamp } = body
  
  if (recipient === actor) { return c.json({ success: true, ignored: true }) }

  try {
      await c.env.DB.prepare(
        "INSERT INTO notifications (id, recipient, actor, action_type, post_id, is_read, timestamp) VALUES (?, ?, ?, ?, ?, 0, ?)"
      ).bind(id, recipient, actor, action_type, post_id, timestamp).run()
      return c.json({ success: true })
  } catch (error: any) {
      return c.json({ success: false, error: error.message }, 500)
  }
})

app.put('/api/notifications/:id/read', async (c) => {
  const id = c.req.param('id')
  try {
      await c.env.DB.prepare("UPDATE notifications SET is_read = 1 WHERE id = ?").bind(id).run()
      return c.json({ success: true })
  } catch (error: any) {
      return c.json({ success: false, error: error.message }, 500)
  }
})

// ==========================================
// ⚡ WebSocket Endpoint (พลังจิตเรียลไทม์ - เฟส 2)
// ==========================================
app.get('/api/ws', async (c) => {
  const upgradeHeader = c.req.header('Upgrade')
  if (upgradeHeader !== 'websocket') {
    return c.text('Expected Upgrade: websocket', 426)
  }
  const id = c.env.TELEPATHY_ROOM.idFromName('global-telepathy-room')
  const stub = c.env.TELEPATHY_ROOM.get(id)
  return stub.fetch(c.req.raw)
})

export default app

// ==========================================
// 🔮 Durable Object สำหรับกระจายคลื่นกระแสจิต (Broadcast)
// ==========================================
export class TelepathyRoom {
  state: DurableObjectState
  sessions: Set<WebSocket>

  constructor(state: DurableObjectState, env: any) {
    this.state = state
    this.sessions = new Set()
  }

  async fetch(request: Request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected Upgrade: websocket", { status: 426 });
    }

    const webSocketPair = new WebSocketPair();
    const client = webSocketPair[0];
    const server = webSocketPair[1];

    this.sessions.add(server);
    server.accept();

    server.addEventListener('message', (event) => {
      for (const session of this.sessions) {
        try {
          session.send(event.data);
        } catch (e) {
          this.sessions.delete(session);
        }
      }
    });

    server.addEventListener('close', () => {
      this.sessions.delete(server);
    });

    server.addEventListener('error', () => {
      this.sessions.delete(server);
    });

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }
}