import { Hono } from 'hono'
import { cors } from 'hono/cors'

type Bindings = {
  DB: D1Database
}

const app = new Hono<{ Bindings: Bindings }>()

app.use('/api/*', cors())

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
// 🔑 ระบบตรวจสอบสิทธิ์แอดมิน 
// ==========================================
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

    return c.json({ success: true, username: user.username, rank_name: user.rank_name || 'วิญญาณเร่ร่อน' });
  } catch (err) {
    return c.json({ success: false, error: 'เกิดข้อผิดพลาดที่แก่นเซิร์ฟเวอร์' }, 500);
  }
});

// ==========================================
// 🚪 จัดการสมาชิก 
// ==========================================
app.get('/api/users', async (c) => {
  const { results } = await c.env.DB.prepare("SELECT * FROM users").all()
  return c.json(results)
})

app.post('/api/users', async (c) => {
  const { username, password, role, rank_name, last_login } = await c.req.json()
  const salt = crypto.randomUUID()
  const hashed = await hashPassword(password, salt)
  try {
    await c.env.DB.prepare(
      "INSERT INTO users (username, password_hash, salt, role, rank_name, password, last_login) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).bind(username, hashed, salt, role || '5', rank_name || 'วิญญาณเร่ร่อน', password, last_login || null).run()
    return c.json({ success: true })
  } catch (e) {
    return c.json({ success: false, message: 'นามแฝงนี้มีผู้ใช้งานแล้ว' }, 400)
  }
})

app.put('/api/users', async (c) => {
  const { username, oldUsername, password, role, rank_name, last_login } = await c.req.json()
  const targetName = oldUsername || username
  try {
    if (password) {
      const salt = crypto.randomUUID()
      const hashed = await hashPassword(password, salt)
      await c.env.DB.prepare(
        "UPDATE users SET username = ?, password_hash = ?, salt = ?, role = ?, rank_name = ?, password = ?, last_login = COALESCE(?, last_login) WHERE username = ?"
      ).bind(username, hashed, salt, role || '5', rank_name || 'วิญญาณเร่ร่อน', password, last_login || null, targetName).run()
    } else {
      await c.env.DB.prepare(
        "UPDATE users SET username = ?, role = ?, rank_name = ?, last_login = COALESCE(?, last_login) WHERE username = ?"
      ).bind(username, role || '5', rank_name || 'วิญญาณเร่ร่อน', last_login || null, targetName).run()
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
  const safeContent = sanitize(body.content)
  const isPinned = (body.pinned === true || body.pinned === 1 || body.pinned === '1') ? 1 : 0;
  
  await c.env.DB.prepare(
    "INSERT INTO posts (id, category, title, content, author, timestamp, pinned) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).bind(body.id, body.category, body.title, safeContent, body.author, body.timestamp, isPinned).run()
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

// 🌟🌟 นำ API กดไลก์กระทู้กลับมา 🌟🌟
app.post('/api/posts/:postId/like', async (c) => {
  const postId = c.req.param('postId')
  try {
    await c.env.DB.prepare("UPDATE posts SET likes = COALESCE(likes, 0) + 1 WHERE id = ?").bind(postId).run()
    const post: any = await c.env.DB.prepare("SELECT likes FROM posts WHERE id = ?").bind(postId).first()
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
  const safeContent = sanitize(body.content)
  await c.env.DB.prepare(
    "INSERT INTO comments (id, post_id, author, content, timestamp) VALUES (?, ?, ?, ?, ?)"
  ).bind(body.id, body.postId, body.author, safeContent, body.timestamp).run()
  await c.env.DB.prepare("UPDATE posts SET replies = replies + 1 WHERE id = ?").bind(body.postId).run()
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

// 🌟🌟 นำ API กดไลก์คอมเมนต์กลับมา 🌟🌟
app.post('/api/comments/:commentId/like', async (c) => {
  const commentId = c.req.param('commentId')
  try {
    await c.env.DB.prepare("UPDATE comments SET likes = COALESCE(likes, 0) + 1 WHERE id = ?").bind(commentId).run()
    const comment: any = await c.env.DB.prepare("SELECT likes FROM comments WHERE id = ?").bind(commentId).first()
    return c.json({ success: true, likes: comment?.likes || 0 })
  } catch (e: any) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

// ==========================================
// 🏠 CMS Index
// ==========================================
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
// 🔔 ระบบกระแสจิต (Notifications)
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

export default app