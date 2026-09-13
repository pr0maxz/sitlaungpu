-- ============================================================
-- schema.sql (ฉบับอัปเดตให้ตรงกับของจริงใน index.ts)
-- ใช้แทนไฟล์เดิมทั้งหมด — รันด้วย:
--   wrangler d1 execute <DB_NAME> --remote --file=schema.sql
-- ทุกคำสั่งใช้ IF NOT EXISTS ดังนั้นรันซ้ำกับ DB ที่มีข้อมูลอยู่แล้วได้อย่างปลอดภัย
-- (จะไม่ลบข้อมูลเดิม แต่ถ้า DB จริงมีคอลัมน์ขาดอยู่ก่อนแล้ว ต้อง ALTER TABLE เพิ่มเอง — ดูหมายเหตุท้ายไฟล์)
-- ============================================================

-- ตารางผู้ใช้งาน
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT DEFAULT '5',              -- '1'=แอดมิน(ปรมัตถ์), '2'-'5'=ยศศิษย์ตามบุญ, อื่นๆ=ยศพิเศษ/ตัวละคร
    rank_name TEXT DEFAULT 'เด็กวัด',    -- ชื่อยศที่แสดงผล เช่น 'เด็กวัด', 'ปฐมภูมิ', หรือ 'ตัวละคร' สำหรับบัญชีพิเศษ
    karma INTEGER DEFAULT 0,            -- แต้มบุญ ใช้คำนวณยศอัตโนมัติ
    last_login INTEGER,                 -- epoch ms
    last_post_time INTEGER,             -- epoch ms กันตั้งกระทู้ถี่เกิน
    last_comment_time INTEGER           -- epoch ms กันคอมเมนต์ถี่เกิน
);

-- ตารางกระทู้
CREATE TABLE IF NOT EXISTS posts (
    id TEXT PRIMARY KEY,
    category TEXT,
    title TEXT,
    content TEXT,
    author TEXT,
    timestamp TEXT,
    views INTEGER DEFAULT 0,
    replies INTEGER DEFAULT 0,
    likes INTEGER DEFAULT 0,
    pinned BOOLEAN DEFAULT 0
);

-- ตารางคอมเมนต์
CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY,
    post_id TEXT,
    author TEXT,
    content TEXT,
    timestamp TEXT,
    likes INTEGER DEFAULT 0
);

-- ตารางยศ/บทบาทแบบกำหนดเอง (แอดมินสร้างเพิ่มได้จากหลังบ้าน)
CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    rank_name TEXT NOT NULL,
    bg_color TEXT,
    text_color TEXT,
    border_color TEXT,
    level INTEGER DEFAULT 5
);

-- ตารางรายงาน (แจ้งลบกระทู้/คอมเมนต์)
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    target_type TEXT,     -- 'post' หรือ 'comment'
    target_id TEXT,
    reporter TEXT,
    reason TEXT,
    timestamp TEXT
);

-- ตารางบุ๊กมาร์ก
CREATE TABLE IF NOT EXISTS bookmarks (
    id TEXT PRIMARY KEY,   -- รูปแบบ: `${username}_${postId}`
    username TEXT NOT NULL,
    post_id TEXT NOT NULL,
    timestamp TEXT
);

-- ตารางแจ้งเตือน
CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    recipient TEXT NOT NULL,
    actor TEXT,
    action_type TEXT,      -- 'mention' | 'reply' | 'comment' | 'like_post' | 'like_comment'
    post_id TEXT,
    is_read INTEGER DEFAULT 0,
    timestamp TEXT
);

-- ตารางเนื้อหาหน้าแรก (CMS) มีแถวเดียวเสมอ (id = 1)
CREATE TABLE IF NOT EXISTS cms (
    id INTEGER PRIMARY KEY,
    heroSubtitle TEXT,
    heroDesc TEXT,
    heroImg TEXT,
    heroBtnText TEXT,
    heroBtnUrl TEXT
);

-- สร้างบัญชี ADMIN ตั้งต้น
INSERT OR IGNORE INTO users (username, password_hash, salt, role, rank_name, karma)
VALUES ('ADMIN', 'c67dd1fbf41eef557161b4028fa681fbece78d8a7ff8b71217643b4f6057a627', 'random_salt_123', '1', 'ปรมัตถ์', 0);

-- ============================================================
-- หมายเหตุสำคัญ: ถ้า D1 จริงของคุณสร้างมาจาก schema.sql เวอร์ชันเก่า (ไม่มีคอลัมน์พวกนี้)
-- CREATE TABLE IF NOT EXISTS จะ "ไม่" เพิ่มคอลัมน์ที่ขาดให้ ต้องรันคำสั่งข้างล่างนี้แยกต่างหาก
-- (ตรวจก่อนว่าคอลัมน์ไหนมีอยู่แล้วบ้างด้วย: PRAGMA table_info(users);)
-- ============================================================
-- ALTER TABLE users ADD COLUMN rank_name TEXT DEFAULT 'เด็กวัด';
-- ALTER TABLE users ADD COLUMN karma INTEGER DEFAULT 0;
-- ALTER TABLE users ADD COLUMN last_login INTEGER;
-- ALTER TABLE users ADD COLUMN last_post_time INTEGER;
-- ALTER TABLE users ADD COLUMN last_comment_time INTEGER;
-- ALTER TABLE posts ADD COLUMN likes INTEGER DEFAULT 0;
-- ALTER TABLE comments ADD COLUMN likes INTEGER DEFAULT 0;