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

// ฟังก์ชัน Hash รหัสผ่าน
async function hashPassword(password: string, salt: string) {
  const encoder = new TextEncoder()
  const data = encoder.encode(password + salt)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

// ฟังก์ชันกัน XSS เบื้องต้น
function sanitize(text: string) {
  if (!text) return text;
  return text.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
             .replace(/on\w+="[^"]*"/gi, '')
             .replace(/on\w+='[^']*'/gi, '')
}

// ==========================================
// 🔑 ระบบตรวจสอบสิทธิ์แอดมิน (Admin Login + รองรับ CMS ทุกแบบ + ส่งยศ)
// ==========================================
app.post('/api/admin/login', async (c) => {
  try {
    const { username, password } = await c.req.json();

    const user = await c.env.DB.prepare(
      "SELECT * FROM users WHERE username = ?"
    ).bind(username).first();

    if (!user) {
      return c.json({ success: false, error: 'ไม่พบนามของท่านในจารึกเมืองนี้' }, 400);
    }

    if (String(user.role) !== '1') {
      return c.json({ success: false, error: 'ตบะบารมีไม่ถึงขั้น ทวารนี้เฉพาะปรมัตถ์เท่านั้น' }, 403);
    }

    // คำนวณ Hash เผื่อกรณีใช้ระบบรหัสเข้ารหัส
    let isValid = false;
    if (user.password_hash && user.salt) {
      const computedHash = await hashPassword(password, user.salt);
      if (user.password_hash === computedHash) {
        isValid = true;
      }
    }

    // รองรับกรณีรหัสผ่านเก็บเป็นข้อความตรงๆ (Plain Text) หรือเปลี่ยนจากหน้า CMS
    if (!isValid && user.password && user.password === password) {
      isValid = true;
    }
    if (!isValid && user.password_hash === password) {
      isValid = true;
    }

    if (!isValid) {
      return c.json({ success: false, error: 'รหัสผ่านอาคมผิดเพี้ยน!' }, 400);
    }

    return c.json({ 
      success: true, 
      username: user.username,
      rank_name: user.rank_name || 'วิญญาณเร่ร่อน'
    });
  } catch (err) {
    return c.json({ success: false, error: 'เกิดข้อผิดพลาดที่แก่นเซิร์ฟเวอร์' }, 500);
  }
});

// ==========================================
// 🚪 หมวดหมู่ API: จัดการผู้ใช้งาน (Users)
// ==========================================

app.get('/api/users', async (c) => {
  const { results } = await c.env.DB.prepare("SELECT username, role, rank_name FROM users").all()
  return c.json(results)
})

app.post('/api/users', async (c) => {
  const { username, password, role, rank_name } = await c.req.json()
  const salt = crypto.randomUUID()
  const hashed = await hashPassword(password, salt)

  try {
    await c.env.DB.prepare(
      "INSERT INTO users (username, password_hash, salt, role, rank_name) VALUES (?, ?, ?, ?, ?)"
    ).bind(username, hashed, salt, role || '5', rank_name || 'วิญญาณเร่ร่อน').run()
    return c.json({ success: true })
  } catch (e) {
    return c.json({ success: false, message: 'นามแฝงนี้มีผู้ใช้งานแล้ว' }, 400)
  }
})

// เส้นทางสำหรับอัปเดตข้อมูลผู้ใช้/รหัสผ่านจากหน้า CMS
app.put('/api/users/:username', async (c) => {
  const username = c.req.param('username')
  const { password, role, rank_name } = await c.req.json()

  try {
    if (password) {
      const salt = crypto.randomUUID()
      const hashed = await hashPassword(password, salt)
      await c.env.DB.prepare(
        "UPDATE users SET password_hash = ?, salt = ?, role = ?, rank_name = ? WHERE username = ?"
      ).bind(hashed, salt, role || '5', rank_name || 'วิญญาณเร่ร่อน', username).run()
    } else {
      await c.env.DB.prepare(
        "UPDATE users SET role = ?, rank_name = ? WHERE username = ?"
      ).bind(role || '5', rank_name || 'วิญญาณเร่ร่อน', username).run()
    }
    return c.json({ success: true })
  } catch (e) {
    return c.json({ success: false, message: 'ไม่สามารถอัปเดตข้อมูลผู้ใช้ได้' }, 400)
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
  const safeContent = sanitize(body.content)
  
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

export default app