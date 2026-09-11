import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { sign, verify, decode } from 'hono/jwt' 

type Bindings = {
  DB: D1Database
  TELEPATHY_ROOM: DurableObjectNamespace
  JWT_SECRET?: string
}

const app = new Hono<{ Bindings: Bindings }>()

app.use('/api/*', cors({
  origin: '*', // ⚠️ ข้อเสนอแนะ: เมื่อระบบนิ่ง ให้เปลี่ยนเป็นโดเมนเว็บคุณ เช่น 'https://sitluangpu.pages.dev' 
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}))

// ⚠️ JWT SECRET: หากไม่ได้ตั้งค่าผ่าน wrangler secret put JWT_SECRET ระบบจะใช้ค่านี้ชั่วคราว
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
             .replace(/on\w+='[^']*'/gi, '');
}

async function generateToken(payload: { username: string; role: string; rank_name: string }, secret: string) {
  return await sign({
    ...payload,
    exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 30)
  }, secret, 'HS256')
}

// 🛡️ [อัปเกรดใหม่] ระบบสแกนกุญแจแบบเจาะลึก พร้อมรายงานสาเหตุ Error
async function getAuthenticatedUser(c: any): Promise<{ user: any, error: string | null }> {
  try {
    const authHeader = c.req.raw.headers.get('Authorization') || c.req.raw.headers.get('authorization');
    if (!authHeader) return { user: null, error: 'Header Missing (เบราว์เซอร์ไม่ได้ส่งกุญแจมา ให้ลองกด Ctrl+F5 เพื่อล้างแคช)' };
    
    const token = authHeader.replace(/^Bearer\s+/i, '').replace(/['"]/g, '').trim();
    if (!token || token === 'undefined' || token === 'null') return { user: null, error: 'Token Empty (กุญแจว่างเปล่า)' };

    const secret = c.env?.JWT_SECRET || DEFAULT_JWT_SECRET;
    const decoded = await verify(token, secret, 'HS256');
    
    return { user: decoded, error: null };
  } catch (e: any) {
    console.error("JWT Verification Error:", e);
    return { user: null, error: `Token Invalid (${e.message})` };
  }
}

function calculateRank(karma: number, currentRole: string, currentRankName: string) {
  const standardRoles = ['2', '3', '4', '5'];
  if (currentRole === '1' || currentRankName === 'ตัวละคร' || (!standardRoles.includes(String(currentRole)) && currentRole !== '')) {
    return { role: currentRole, rank_name: currentRankName, nextRankMsg: 'ยศพิเศษแต่งตั้ง / ข้อยกเว้น' };
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
  } catch (e) { console.error("Error adding karma:", e) }
}

const loginAttempts = new Map<string, { count: number, lockUntil: number }>();

function checkLoginRateLimit(ip: string): { allowed: boolean, waitTimeStr?: string } {
  const now = Date.now();
  const attempt = loginAttempts.get(ip);
  if (attempt) {
    if (attempt.lockUntil > now) {
      const waitMins = Math.ceil((attempt.lockUntil - now) / 60000);
      return { allowed: false, waitTimeStr: `${waitMins} นาที` };
    }
    if (attempt.lockUntil > 0 && attempt.lockUntil <= now) {
      loginAttempts.delete(ip); 
    }
  }
  return { allowed: true };
}

function recordFailedLogin(ip: string) {
  if (ip === 'unknown') return;
  const now = Date.now();
  const attempt = loginAttempts.get(ip) || { count: 0, lockUntil: 0 };
  attempt.count += 1;
  if (attempt.count >= 5) attempt.lockUntil = now + (15 * 60 * 1000);
  loginAttempts.set(ip, attempt);
}

function resetLoginAttempts(ip: string) {
  loginAttempts.delete(ip);
}

// === AUTH & USERS ROUTES ===

app.post('/api/login', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  const rateLimit = checkLoginRateLimit(ip);
  if (!rateLimit.allowed) return c.json({ success: false, error: `ระงับชั่วคราวจากการเข้าระบบผิดพลาดเกินขีดจำกัด โปรดรออีก ${rateLimit.waitTimeStr}` }, 429);

  try {
    const { username, password } = await c.req.json()
    const user: any = await c.env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first()
    
    if (!user) {
      recordFailedLogin(ip);
      return c.json({ success: false, error: 'ไม่พบนามแฝงนี้ในระบบ' }, 400);
    }

    let isValid = false
    if (user.password_hash && user.salt) {
      const computedHash = await hashPassword(password, user.salt)
      if (user.password_hash === computedHash) isValid = true
    }
    
    if (!isValid) {
      recordFailedLogin(ip);
      return c.json({ success: false, error: 'รหัสผ่านลับไม่ถูกต้อง' }, 400);
    }

    resetLoginAttempts(ip);

    const now = Date.now()
    try { await c.env.DB.prepare("UPDATE users SET last_login = ? WHERE username = ?").bind(now, user.username).run() } catch(e) {}

    const secret = c.env.JWT_SECRET || DEFAULT_JWT_SECRET
    const token = await generateToken({ username: user.username, role: String(user.role || '5'), rank_name: user.rank_name || 'เด็กวัด' }, secret)
    const rankInfo = calculateRank(user.karma || 0, String(user.role), user.rank_name)

    return c.json({ success: true, token, username: user.username, role: user.role, rank_name: user.rank_name, karma: user.karma || 0, nextRankMsg: rankInfo.nextRankMsg })
  } catch (err: any) {
    return c.json({ success: false, error: 'เกิดข้อผิดพลาดในการตรวจสอบตัวตน' }, 500)
  }
})

app.post('/api/admin/login', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  const rateLimit = checkLoginRateLimit(ip);
  if (!rateLimit.allowed) return c.json({ success: false, error: `ระบบป้องกันทำงาน! อาณาเขตถูกปิดกั้น โปรดรออีก ${rateLimit.waitTimeStr}` }, 429);

  try {
    const { username, password } = await c.req.json();
    const user: any = await c.env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
    
    if (!user) {
      recordFailedLogin(ip);
      return c.json({ success: false, error: 'ไม่พบนามของท่านในจารึกเมืองนี้' }, 400);
    }

    if (String(user.role) !== '1') {
      recordFailedLogin(ip);
      return c.json({ success: false, error: 'ตบะบารมีไม่ถึงขั้น ทวารนี้เฉพาะปรมัตถ์เท่านั้น' }, 403);
    }

    let isValid = false;
    if (user.password_hash && user.salt) {
      const computedHash = await hashPassword(password, user.salt);
      if (user.password_hash === computedHash) isValid = true;
    }

    if (!isValid) {
      recordFailedLogin(ip);
      return c.json({ success: false, error: 'รหัสผ่านอาคมผิดเพี้ยน!' }, 400);
    }

    resetLoginAttempts(ip);

    try { await c.env.DB.prepare("UPDATE users SET last_login = ? WHERE username = ?").bind(Date.now(), user.username).run(); } catch(e) {}

    const secret = c.env.JWT_SECRET || DEFAULT_JWT_SECRET
    const token = await generateToken({ username: user.username, role: '1', rank_name: user.rank_name || 'ปรมัตถ์' }, secret)

    return c.json({ success: true, token, username: user.username, rank_name: user.rank_name || 'เด็กวัด' });
  } catch (err) { return c.json({ success: false, error: 'เกิดข้อผิดพลาดที่แก่นเซิร์ฟเวอร์' }, 500); }
});

app.get('/api/me', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ authenticated: false, error: authResult.error }, 401)
  const authUser = authResult.user;

  const user: any = await c.env.DB.prepare("SELECT username, role, rank_name, karma, last_login FROM users WHERE username = ?").bind(authUser.username).first()
  if (!user) return c.json({ authenticated: false }, 404)
  const rankInfo = calculateRank(user.karma || 0, String(user.role), user.rank_name)
  return c.json({ authenticated: true, user: { ...user, nextRankMsg: rankInfo.nextRankMsg } })
})

app.get('/api/users', async (c) => {
  const { results } = await c.env.DB.prepare("SELECT username, role, rank_name, karma, last_login FROM users").all()
  const usersWithKarmaInfo = results.map((u: any) => {
    const rankInfo = calculateRank(u.karma || 0, String(u.role), u.rank_name);
    return { ...u, nextRankMsg: rankInfo.nextRankMsg }
  })
  return c.json(usersWithKarmaInfo)
})

app.post('/api/users', async (c) => {
  const body = await c.req.json()
  const { username, password, role, rank_name, last_login, bot_check } = body
  
  if (bot_check !== 'สัตยาสาบาน') return c.json({ success: false, message: 'โดนสกัดกั้น! คำปฏิญาณยืนยันตัวตนไม่ถูกต้อง' }, 403);

  if (!/^[\u0E00-\u0E7F]+$/.test(username)) {
      return c.json({ success: false, message: 'นามแฝงอนุญาตเฉพาะ "อักขระภาษาไทย" และห้ามเว้นวรรคเด็ดขาด!' }, 400);
  }

  const salt = crypto.randomUUID()
  const hashed = await hashPassword(password, salt)
  try {
    await c.env.DB.prepare(
      "INSERT INTO users (username, password_hash, salt, role, rank_name, last_login, karma) VALUES (?, ?, ?, ?, ?, ?, 0)"
    ).bind(username, hashed, salt, role || '5', rank_name || 'เด็กวัด', last_login || null).run()
    
    const secret = c.env.JWT_SECRET || DEFAULT_JWT_SECRET
    const token = await generateToken({ username, role: role || '5', rank_name: rank_name || 'เด็กวัด' }, secret)
    return c.json({ success: true, token, username })
  } catch (e) {
    return c.json({ success: false, message: 'นามแฝงนี้มีผู้ใช้งานแล้ว' }, 400)
  }
})

app.put('/api/users', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user || String(authResult.user.role) !== '1') return c.json({ success: false, error: 'Forbidden' }, 403)

  const { username, oldUsername, password, role, rank_name, last_login, karma } = await c.req.json()
  const targetName = oldUsername || username
  const currentKarma = karma || 0
  
  if (!/^[\u0E00-\u0E7F]+$/.test(username)) {
      return c.json({ success: false, message: 'นามแฝงอนุญาตเฉพาะ "อักขระภาษาไทย" และห้ามเว้นวรรคเด็ดขาด!' }, 400);
  }

  try {
    if (password) {
      const salt = crypto.randomUUID()
      const hashed = await hashPassword(password, salt)
      await c.env.DB.prepare(
        "UPDATE users SET username = ?, password_hash = ?, salt = ?, role = ?, rank_name = ?, last_login = COALESCE(?, last_login), karma = COALESCE(?, karma) WHERE username = ?"
      ).bind(username, hashed, salt, role || '5', rank_name || 'เด็กวัด', last_login || null, currentKarma, targetName).run()
    } else {
      await c.env.DB.prepare(
        "UPDATE users SET username = ?, role = ?, rank_name = ?, last_login = COALESCE(?, last_login), karma = COALESCE(?, karma) WHERE username = ?"
      ).bind(username, role || '5', rank_name || 'เด็กวัด', last_login || null, currentKarma, targetName).run()
    }
    return c.json({ success: true })
  } catch (e) { return c.json({ success: false, message: 'ไม่สามารถอัปเดตข้อมูลผู้ใช้ได้' }, 400) }
})

app.delete('/api/users/:username', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user || String(authResult.user.role) !== '1') return c.json({ success: false, error: 'Forbidden' }, 403)

  const username = c.req.param('username')
  await c.env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run()
  return c.json({ success: true })
})

// === POSTS & COMMENTS ROUTES ===

app.get('/api/posts', async (c) => {
  const { results } = await c.env.DB.prepare("SELECT * FROM posts ORDER BY id DESC").all()
  return c.json(results)
})

app.post('/api/posts', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)
  const author = authResult.user.username;

  const body = await c.req.json()
  const now = Date.now();
  const user: any = await c.env.DB.prepare("SELECT last_post_time, role FROM users WHERE username = ?").bind(author).first();
  if (user && String(user.role) !== '1') {
    const lastPostTime = user.last_post_time || 0;
    if (now - lastPostTime < 30000) {
      const timeLeft = Math.ceil((30000 - (now - lastPostTime)) / 1000);
      return c.json({ success: false, error: `ท่านร่ายเวทมนตร์ถี่เกินไป โปรดพักหายใจอีก ${timeLeft} วินาที` }, 429);
    }
  }

  const safeContent = sanitize(body.content)
  const isPinned = (body.pinned === true || body.pinned === 1 || body.pinned === '1') ? 1 : 0;
  
  await c.env.DB.prepare(
    "INSERT INTO posts (id, category, title, content, author, timestamp, pinned) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).bind(body.id, body.category, body.title, safeContent, author, body.timestamp, isPinned).run()
  
  await c.env.DB.prepare("UPDATE users SET last_post_time = ? WHERE username = ?").bind(now, author).run();
  await addKarma(c.env.DB, author, 2);

  // 🛡️ [เพิ่มใหม่] สร้างแจ้งเตือนเมื่อมีการ Mention ในกระทู้หลัก
  try {
      const mentionRegex = /@([\u0E00-\u0E7Fa-zA-Z0-9_-]+)/g;
      const combinedText = `${body.title} ${safeContent}`;
      const matches = [...combinedText.matchAll(mentionRegex)];
      const mentionedUsers = [...new Set(matches.map(m => m[1]))];
      const notiTimeStrISO = new Date().toISOString();
      
      for (const mentionedUser of mentionedUsers) {
          if (mentionedUser !== author) {
              const notiId = Date.now().toString() + Math.floor(Math.random() * 10000);
              await c.env.DB.prepare(
                  "INSERT INTO notifications (id, recipient, actor, action_type, post_id, is_read, timestamp) VALUES (?, ?, ?, 'mention', ?, 0, ?)"
              ).bind(notiId, mentionedUser, author, body.id, notiTimeStrISO).run().catch(()=>{});
          }
      }
  } catch (notiErr) { console.error(notiErr) }

  return c.json({ success: true })
})

app.put('/api/posts', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)
  const authUser = authResult.user;

  const body = await c.req.json()
  const post: any = await c.env.DB.prepare("SELECT author FROM posts WHERE id = ?").bind(body.id).first()
  if (!post) return c.json({ success: false, error: 'ไม่พบศิลาจารึกที่ต้องการแก้ไข' }, 404)

  if (String(authUser.role) !== '1' && authUser.username !== post.author) {
      return c.json({ success: false, error: 'Forbidden: ท่านไม่มีสิทธิ์แก้ไขจารึกของผู้อื่น' }, 403)
  }

  const safeContent = sanitize(body.content || '')
  const isPinned = (body.pinned === true || body.pinned === 1 || body.pinned === '1') ? 1 : 0;

  try {
    await c.env.DB.prepare(
      "UPDATE posts SET category = ?, title = ?, content = ?, pinned = ? WHERE id = ?"
    ).bind(body.category, body.title, safeContent, isPinned, body.id).run()
    return c.json({ success: true })
  } catch (e: any) { return c.json({ success: false, error: e.message }, 500) }
})

app.get('/api/posts/:id', async (c) => {
  const id = c.req.param('id')
  try { await c.env.DB.prepare("UPDATE posts SET views = COALESCE(views, 0) + 1 WHERE id = ?").bind(id).run() } catch (e) {}
  const post = await c.env.DB.prepare("SELECT * FROM posts WHERE id = ?").bind(id).first()
  return c.json(post)
})

app.delete('/api/posts/:id', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)
  const authUser = authResult.user;

  const id = c.req.param('id')
  const post: any = await c.env.DB.prepare("SELECT author FROM posts WHERE id = ?").bind(id).first()
  
  if (post && String(authUser.role) !== '1' && authUser.username !== post.author) {
    return c.json({ success: false, error: 'Forbidden' }, 403)
  }

  await c.env.DB.prepare("DELETE FROM posts WHERE id = ?").bind(id).run()
  await c.env.DB.prepare("DELETE FROM comments WHERE post_id = ?").bind(id).run()
  await c.env.DB.prepare("DELETE FROM bookmarks WHERE post_id = ?").bind(id).run()
  await c.env.DB.prepare("DELETE FROM notifications WHERE post_id LIKE ?").bind(`${id}%`).run().catch(()=>{})
  return c.json({ success: true })
})

app.post('/api/posts/:postId/like', async (c) => {
  const postId = c.req.param('postId')
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)
  const actor = authResult.user.username;

  try {
    await c.env.DB.prepare("UPDATE posts SET likes = COALESCE(likes, 0) + 1 WHERE id = ?").bind(postId).run()
    const post: any = await c.env.DB.prepare("SELECT * FROM posts WHERE id = ?").bind(postId).first()
    
    if (post && post.author && post.author !== actor) {
      const notiId = Date.now().toString()
      const timeStr = new Date().toISOString()
      await c.env.DB.prepare(
        "INSERT INTO notifications (id, recipient, actor, action_type, post_id, is_read, timestamp) VALUES (?, ?, ?, 'like_post', ?, 0, ?)"
      ).bind(notiId, post.author, actor, postId, timeStr).run().catch(() => {})
      await addKarma(c.env.DB, post.author, 1);
    }
    return c.json({ success: true, likes: post?.likes || 0 })
  } catch (e: any) { return c.json({ success: false, error: e.message }, 500) }
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
  const author = authResult.user.username;

  const body = await c.req.json()
  const now = Date.now();
  const user: any = await c.env.DB.prepare("SELECT last_comment_time, role FROM users WHERE username = ?").bind(author).first();
  if (user && String(user.role) !== '1') {
    const lastCommentTime = user.last_comment_time || 0;
    if (now - lastCommentTime < 15000) {
      const timeLeft = Math.ceil((15000 - (now - lastCommentTime)) / 1000);
      return c.json({ success: false, error: `ท่านส่งกระแสจิตถี่เกินไป โปรดพักอีก ${timeLeft} วินาที` }, 429);
    }
  }

  const safeContent = sanitize(body.content)
  await c.env.DB.prepare(
    "INSERT INTO comments (id, post_id, author, content, timestamp) VALUES (?, ?, ?, ?, ?)"
  ).bind(body.id, body.postId, author, safeContent, body.timestamp).run()
  await c.env.DB.prepare("UPDATE posts SET replies = replies + 1 WHERE id = ?").bind(body.postId).run()
  await c.env.DB.prepare("UPDATE users SET last_comment_time = ? WHERE username = ?").bind(now, author).run();
  await addKarma(c.env.DB, author, 1);

  // 🛡️ [เพิ่มใหม่] สร้างการแจ้งเตือนจากฝั่ง Backend โดยตรง (ชัวร์ 100%)
  try {
      const post: any = await c.env.DB.prepare("SELECT author FROM posts WHERE id = ?").bind(body.postId).first();
      const targetCommentId = `${body.postId}#comment-${body.id}`;
      const notiTimeStrISO = new Date().toISOString();

      // 1. แจ้งเตือนคนถูกตอบกลับ (Reply)
      let repliedAuthor = null;
      const replyMatch = safeContent.match(/\[AUTHOR:([^\]]+)\]/);
      if (replyMatch && replyMatch[1]) {
          repliedAuthor = replyMatch[1];
          if (repliedAuthor !== author) {
              const notiId1 = Date.now().toString() + Math.floor(Math.random() * 1000);
              await c.env.DB.prepare(
                  "INSERT INTO notifications (id, recipient, actor, action_type, post_id, is_read, timestamp) VALUES (?, ?, ?, 'reply', ?, 0, ?)"
              ).bind(notiId1, repliedAuthor, author, targetCommentId, notiTimeStrISO).run().catch(()=>{});
          }
      }

      // 2. แจ้งเตือนคนถูกแท็ก (Mention)
      const mentionRegex = /@([\u0E00-\u0E7Fa-zA-Z0-9_-]+)/g;
      const matches = [...safeContent.matchAll(mentionRegex)];
      const mentionedUsers = [...new Set(matches.map(m => m[1]))];
      
      for (const mentionedUser of mentionedUsers) {
          if (mentionedUser !== author && mentionedUser !== repliedAuthor) {
              const notiId2 = Date.now().toString() + Math.floor(Math.random() * 10000);
              await c.env.DB.prepare(
                  "INSERT INTO notifications (id, recipient, actor, action_type, post_id, is_read, timestamp) VALUES (?, ?, ?, 'mention', ?, 0, ?)"
              ).bind(notiId2, mentionedUser, author, targetCommentId, notiTimeStrISO).run().catch(()=>{});
          }
      }

      // 3. แจ้งเตือนเจ้าของกระทู้ (ถ้าไม่ได้ถูกตอบกลับหรือถูกแท็กไปแล้ว)
      if (post && post.author && post.author !== author && post.author !== repliedAuthor && !mentionedUsers.includes(post.author)) {
          const notiId3 = Date.now().toString() + Math.floor(Math.random() * 100000);
          await c.env.DB.prepare(
              "INSERT INTO notifications (id, recipient, actor, action_type, post_id, is_read, timestamp) VALUES (?, ?, ?, 'comment', ?, 0, ?)"
          ).bind(notiId3, post.author, author, targetCommentId, notiTimeStrISO).run().catch(()=>{});
      }
  } catch (notiErr) { console.error("Notification Error:", notiErr) }

  return c.json({ success: true })
})

app.delete('/api/comments/:id', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)
  const authUser = authResult.user;

  const id = c.req.param('id')
  const comment: any = await c.env.DB.prepare("SELECT post_id, author FROM comments WHERE id = ?").bind(id).first()
  
  if (comment && String(authUser.role) !== '1' && authUser.username !== comment.author) {
    return c.json({ success: false, error: 'Forbidden' }, 403)
  }

  if (comment) {
    await c.env.DB.prepare("UPDATE posts SET replies = MAX(0, replies - 1) WHERE id = ?").bind(comment.post_id).run()
  }
  await c.env.DB.prepare("DELETE FROM comments WHERE id = ?").bind(id).run()
  return c.json({ success: true })
})

app.post('/api/comments/:commentId/like', async (c) => {
  const commentId = c.req.param('commentId')
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)
  const actor = authResult.user.username;

  try {
    await c.env.DB.prepare("UPDATE comments SET likes = COALESCE(likes, 0) + 1 WHERE id = ?").bind(commentId).run()
    const comment: any = await c.env.DB.prepare("SELECT * FROM comments WHERE id = ?").bind(commentId).first()
    
    if (comment && comment.author && comment.author !== actor) {
      const notiId = Date.now().toString()
      const timeStr = new Date().toISOString()
      await c.env.DB.prepare(
        "INSERT INTO notifications (id, recipient, actor, action_type, post_id, is_read, timestamp) VALUES (?, ?, ?, 'like_comment', ?, 0, ?)"
      ).bind(notiId, comment.author, actor, `${comment.post_id}#comment-${commentId}`, timeStr).run().catch(() => {})
      await addKarma(c.env.DB, comment.author, 1);
    }
    return c.json({ success: true, likes: comment?.likes || 0 })
  } catch (e: any) { return c.json({ success: false, error: e.message }, 500) }
})

// === OTHERS (ROLES, REPORTS, BOOKMARKS, CMS) ===

app.get('/api/roles', async (c) => {
  try {
    const { results } = await c.env.DB.prepare("SELECT * FROM roles ORDER BY level ASC, rank_name ASC").all()
    return c.json(results || [])
  } catch(e) { return c.json([]) }
})

app.post('/api/roles', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user || String(authResult.user.role) !== '1') return c.json({ success: false, error: 'Forbidden' }, 403)
  
  const body = await c.req.json()
  try {
    const id = `dynamic_${crypto.randomUUID().substring(0, 8)}`
    await c.env.DB.prepare(
      "INSERT INTO roles (id, rank_name, bg_color, text_color, border_color, level) VALUES (?, ?, ?, ?, ?, ?)"
    ).bind(id, body.rank_name, body.bg_color, body.text_color, body.border_color || '', body.level || 5).run()
    return c.json({ success: true, id })
  } catch (e: any) { return c.json({ success: false, error: e.message }, 500) }
})

app.delete('/api/roles/:id', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user || String(authResult.user.role) !== '1') return c.json({ success: false, error: 'Forbidden' }, 403)
  
  const id = c.req.param('id')
  try {
    await c.env.DB.prepare("DELETE FROM roles WHERE id = ?").bind(id).run()
    return c.json({ success: true })
  } catch (e: any) { return c.json({ success: false, error: e.message }, 500) }
})

app.get('/api/reports', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user || String(authResult.user.role) !== '1') return c.json([], 403)

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
  } catch (error: any) { return c.json({ success: false, error: error.message }, 500) }
})

app.delete('/api/reports/:id', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user || String(authResult.user.role) !== '1') return c.json({ success: false, error: 'Forbidden' }, 403)
  
  const id = c.req.param('id')
  try {
    await c.env.DB.prepare("DELETE FROM reports WHERE id = ?").bind(id).run()
    return c.json({ success: true })
  } catch (error: any) { return c.json({ success: false, error: error.message }, 500) }
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
  
  const body = await c.req.json().catch(() => ({}))
  const postId = body.postId || body.post_id
  if (!postId) return c.json({ success: false, error: 'ไม่พบรหัสจารึก' }, 400)
  try {
    const id = `${authResult.user.username}_${postId}`
    const timeStr = new Date().toISOString()
    await c.env.DB.prepare(
      "INSERT OR REPLACE INTO bookmarks (id, username, post_id, timestamp) VALUES (?, ?, ?, ?)"
    ).bind(id, authResult.user.username, String(postId), timeStr).run()
    return c.json({ success: true })
  } catch (e: any) { return c.json({ success: false, error: e.message }, 500) }
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
  } catch (e: any) { return c.json({ success: false, error: e.message }, 500) }
})

app.get('/api/cms', async (c) => {
  const cms = await c.env.DB.prepare("SELECT * FROM cms WHERE id = 1").first()
  return c.json(cms || {})
})

app.post('/api/cms', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user || String(authResult.user.role) !== '1') return c.json({ success: false, error: 'Forbidden' }, 403)
  
  const body = await c.req.json()
  await c.env.DB.prepare(
    "INSERT INTO cms (id, heroSubtitle, heroDesc, heroImg, heroBtnText, heroBtnUrl) VALUES (1, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET heroSubtitle = ?, heroDesc = ?, heroImg = ?, heroBtnText = ?, heroBtnUrl = ?"
  ).bind(body.heroSubtitle || '', body.heroDesc || '', body.heroImg || '', body.heroBtnText || '', body.heroBtnUrl || '', body.heroSubtitle || '', body.heroDesc || '', body.heroImg || '', body.heroBtnText || '', body.heroBtnUrl || '').run()
  return c.json({ success: true })
})

app.get('/api/notifications/:username', async (c) => {
  const username = c.req.param('username')
  try {
    const { results } = await c.env.DB.prepare("SELECT * FROM notifications WHERE recipient = ? ORDER BY id DESC LIMIT 30").bind(username).all()
    return c.json(results || [])
  } catch (e) { return c.json([]) }
})

app.post('/api/notifications', async (c) => {
  // 🛡️ ระบบนี้ถูกย้ายไปทำงานใน Backend แบบออโต้แล้ว (ใส่ไว้กัน Error เฉยๆ เผื่อเว็บหน้าบ้านลืมลบโค้ด)
  return c.json({ success: true, ignored: true });
})

app.put('/api/notifications/:id/read', async (c) => {
  const authResult = await getAuthenticatedUser(c)
  if (!authResult.user) return c.json({ success: false, error: `Unauthorized: ${authResult.error}` }, 401)

  const id = c.req.param('id')
  try {
      await c.env.DB.prepare("UPDATE notifications SET is_read = 1 WHERE id = ?").bind(id).run()
      return c.json({ success: true })
  } catch (error: any) { return c.json({ success: false, error: error.message }, 500) }
})

app.get('/sitemap.xml', async (c) => {
  try {
    const { results } = await c.env.DB.prepare("SELECT id, timestamp FROM posts ORDER BY id DESC").all();
    const baseUrl = 'https://sitluangpu.pages.dev'; 
    let xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n`;
    xml += `  <url>\n    <loc>${baseUrl}/index.html</loc>\n    <priority>1.0</priority>\n  </url>\n`;
    xml += `  <url>\n    <loc>${baseUrl}/webboard.html</loc>\n    <priority>0.9</priority>\n  </url>\n`;
    if (results) { results.forEach((post: any) => { xml += `  <url>\n    <loc>${baseUrl}/post.html?id=${post.id}</loc>\n    <priority>0.8</priority>\n  </url>\n`; }); }
    xml += `</urlset>`;
    c.header('Content-Type', 'application/xml');
    return c.text(xml);
  } catch (e: any) { return c.text('Error generating sitemap', 500); }
});

app.get('/api/ws', async (c) => {
  const upgradeHeader = c.req.header('Upgrade')
  if (upgradeHeader !== 'websocket') return c.text('Expected Upgrade: websocket', 426)
  const id = c.env.TELEPATHY_ROOM.idFromName('global-telepathy-room')
  const stub = c.env.TELEPATHY_ROOM.get(id)
  return stub.fetch(c.req.raw)
})

export default app

export class TelepathyRoom {
  state: DurableObjectState
  sessions: Set<WebSocket>
  constructor(state: DurableObjectState, env: any) {
    this.state = state
    this.sessions = new Set()
  }
  async fetch(request: Request) {
    if (request.headers.get("Upgrade") !== "websocket") return new Response("Expected Upgrade: websocket", { status: 426 });
    const webSocketPair = new WebSocketPair();
    const client = webSocketPair[0];
    const server = webSocketPair[1];
    this.sessions.add(server);
    server.accept();
    server.addEventListener('message', (event) => {
      for (const session of this.sessions) {
        try { session.send(event.data); } catch (e) { this.sessions.delete(session); }
      }
    });
    server.addEventListener('close', () => { this.sessions.delete(server); });
    server.addEventListener('error', () => { this.sessions.delete(server); });
    return new Response(null, { status: 101, webSocket: client, });
  }
}