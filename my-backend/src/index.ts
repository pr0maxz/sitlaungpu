import { Hono } from 'hono'
import { cors } from 'hono/cors'

// กำหนดให้ระบบรู้ว่าเรามี D1 Database ที่ชื่อว่า DB
type Bindings = {
  DB: D1Database
}

const app = new Hono<{ Bindings: Bindings }>()

// 🌟 เปิดทางเชื่อมมิติ (CORS) ให้หน้าเว็บ Frontend ยิงมาหา API นี้ได้
app.use('/api/*', cors())

// ==========================================
// 🔮 หมวดหมู่ฟังก์ชันเวทมนตร์ (Helpers)
// ==========================================

// ฟังก์ชัน Hash รหัสผ่าน (ชำระล้างไม่ให้ใครอ่านออก)
async function hashPassword(password: string, salt: string) {
  const encoder = new TextEncoder()
  const data = encoder.encode(password + salt)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

// ฟังก์ชันกัน XSS เบื้องต้น (ป้องกันมนต์ดำไซเบอร์)
function sanitize(text: string) {
  if (!text) return text;
  return text.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
             .replace(/on\w+="[^"]*"/gi, '') // ลบพวก onerror=, onclick=
             .replace(/on\w+='[^']*'/gi, '')
}

// ==========================================
// 🚪 หมวดหมู่ API: จัดการผู้ใช้งาน (Users)
// ==========================================

app.get('/api/users', async (c) => {
  // ดึงข้อมูลมาแค่ชื่อและยศ (ห้ามดึงรหัสผ่านเด็ดขาด)
  const { results } = await c.env.DB.prepare("SELECT username, role FROM users").all()
  return c.json(results)
})

app.post('/api/users', async (c) => {
  const { username, password, role } = await c.req.json()
  const salt = crypto.randomUUID()
  const hashed = await hashPassword(password, salt)

  try {
    await c.env.DB.prepare("INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)").bind(username, hashed, salt, role || '5').run()
    return c.json({ success: true })
  } catch (e) {
    return c.json({ success: false, message: 'นามแฝงนี้มีผู้ใช้งานแล้ว' }, 400)
  }
})

// ==========================================
// 📜 หมวดหมู่ API: จัดการกระทู้ (Posts)
// ==========================================

app.get('/api/posts', async (c) => {
  const { results } = await c.env.DB.prepare("SELECT * FROM posts ORDER BY id DESC").all()
  return c.json(results)
})

app.post('/api/posts', async (c) => {
  const body = await c.req.json()
  const safeContent = sanitize(body.content) // กรองคำสั่งอันตรายออกก่อน
  
  await c.env.DB.prepare(
    "INSERT INTO posts (id, category, title, content, author, timestamp, pinned) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).bind(body.id, body.category, body.title, safeContent, body.author, body.timestamp, body.pinned ? 1 : 0).run()
  
  return c.json({ success: true })
})

app.get('/api/posts/:id', async (c) => {
  const id = c.req.param('id')
  const post = await c.env.DB.prepare("SELECT * FROM posts WHERE id = ?").bind(id).first()
  return c.json(post)
})

app.delete('/api/posts/:id', async (c) => {
  const id = c.req.param('id')
  await c.env.DB.prepare("DELETE FROM posts WHERE id = ?").bind(id).run()
  // ลบคอมเมนต์ที่ผูกกับกระทู้นี้ทิ้งด้วย (Cascade Delete)
  await c.env.DB.prepare("DELETE FROM comments WHERE post_id = ?").bind(id).run()
  return c.json({ success: true })
})

// ==========================================
// 💬 หมวดหมู่ API: จัดการคอมเมนต์ (Comments)
// ==========================================

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
  
  // สั่งเพิ่มจำนวนคนตอบ (replies) ในตาราง posts อัตโนมัติ
  await c.env.DB.prepare("UPDATE posts SET replies = replies + 1 WHERE id = ?").bind(body.postId).run()
  
  return c.json({ success: true })
})

app.delete('/api/comments/:id', async (c) => {
  const id = c.req.param('id')
  
  // หายอดรีพลายกลับให้กระทู้หลัก ก่อนลบคอมเมนต์
  const comment: any = await c.env.DB.prepare("SELECT post_id FROM comments WHERE id = ?").bind(id).first()
  if (comment) {
    await c.env.DB.prepare("UPDATE posts SET replies = MAX(0, replies - 1) WHERE id = ?").bind(comment.post_id).run()
  }
  
  await c.env.DB.prepare("DELETE FROM comments WHERE id = ?").bind(id).run()
  return c.json({ success: true })
})

export default app