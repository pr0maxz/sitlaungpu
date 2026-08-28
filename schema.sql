-- ตารางผู้ใช้งาน (เก็บ Password แบบ Hash และ Salt)
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT DEFAULT '5'
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
    pinned BOOLEAN DEFAULT 0
);

-- ตารางคอมเมนต์
CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY,
    post_id TEXT,
    author TEXT,
    content TEXT,
    timestamp TEXT
);

-- สร้างบัญชี ADMIN ตั้งต้น
INSERT OR IGNORE INTO users (username, password_hash, salt, role) 
VALUES ('ADMIN', 'c67dd1fbf41eef557161b4028fa681fbece78d8a7ff8b71217643b4f6057a627', 'random_salt_123', '1');