// _middleware.js — Cloudflare Pages Middleware
// แก้ไข:
//   1. escape ค่าก่อนยัดใน attribute (กัน XSS จากหัวข้อกระทู้)
//   2. ทำงานเฉพาะบอต social crawler (ไม่ให้ผู้ใช้รอ API โดยเปล่าประโยชน์)
//   3. URL pattern เฉพาะ /post และ /post.html (ไม่ครอบ /create_post.html)
//   4. ส่ง ?noview=1 เพื่อไม่ให้ backend นับยอดวิวซ้ำ
//   5. ลบ <meta og:*> เดิมใน post.html ก่อนฉีดอันใหม่ (กันค่าซ้ำ)
//   6. เพิ่ม og:locale, og:site_name, twitter:card

const API_BASE = 'https://my-backend.pr0maxz.workers.dev/api';
const FALLBACK_IMAGE = 'https://res.cloudinary.com/kjdb7wyp/image/upload/v1788019626/logo.png';
const SITE_NAME = 'ศิษย์หลวงปู่';
const MAX_DESC_LEN = 160;

// รายชื่อ User-Agent ของบอตที่ต้องการ og: tags (ไม่ case-sensitive)
const BOT_UA_RE = /facebookexternalhit|facebot|twitterbot|slackbot|linkedinbot|whatsapp|discordbot|telegrambot|line-poker|applebot|googlebot|bingbot|duckduckbot|embedly|pinterest|vkshare|xing-contenttabreceiver|redditbot|quora|outbrain|nuzzel|flipboard|pocket|iframely/i;

// Escape สำหรับใช้ใน HTML attribute (content="..." และ href="...")
function attrEsc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

// กัน URL แบบ javascript:/data: ที่ไม่ปลอดภัย
function safeUrl(u) {
    if (!u || typeof u !== 'string') return '';
    return /^\s*(javascript|data|vbscript)\s*:/i.test(u) ? '' : u;
}

// ตรวจว่าเป็น User-Agent ของบอต social crawler
function isCrawlerBot(request) {
    const ua = request.headers.get('User-Agent') || '';
    return BOT_UA_RE.test(ua);
}

// ดึงข้อมูลกระทู้จาก backend (ใช้ ?noview=1 ไม่ให้นับยอดวิวซ้ำ)
async function fetchPostData(postId) {
    // postId ต้องผ่าน /^[\w-]{1,64}$/ เท่านั้น (กัน path traversal)
    if (!/^[\w-]{1,64}$/.test(postId)) return null;
    const res = await fetch(`${API_BASE}/posts/${encodeURIComponent(postId)}?noview=1`, {
        headers: { 'User-Agent': 'SiyLuangpuBot/1.0 (og-tag-generator)' }
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (!data || !data.title) return null;
    return data;
}

// แปลง content (HTML) → ข้อความ และตัดให้พอดี
function makeDescription(content) {
    if (!content || typeof content !== 'string') return '';
    // ถอด bracket tokens เช่น [REPLY_TO:...], [AUTHOR:...], [YOUTUBE:...]
    let text = content
        .replace(/\[REPLY_TO:[^\]]*\]/g, '')
        .replace(/\[AUTHOR:[^\]]*\]/g, '')
        .replace(/\[YOUTUBE:[^\]]*\]/g, '')
        // ถอดแท็ก HTML ทั้งหมด
        .replace(/<[^>]*>/g, ' ')
        // ถอด HTML entities พื้นฐาน
        .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, ' ')
        // รวบช่องว่าง
        .replace(/\s+/g, ' ')
        .trim();
    return text.length > MAX_DESC_LEN ? text.slice(0, MAX_DESC_LEN) + '…' : text;
}

// หารูปภาพแรกในเนื้อหา
function extractFirstImage(content) {
    if (!content || typeof content !== 'string') return '';
    // รองรับทั้ง src="..." และ src='...'
    const m = content.match(/<img[^>]+src=["']?(https?:\/\/[^"'\s>]+)["']?/i);
    return m ? safeUrl(m[1]) : '';
}

// HTMLRewriter handler: ลบ og:* เดิม แล้วฉีดอันใหม่ต่อท้าย <head>
class OgTagRewriter {
    constructor(tags) {
        // tags: object ที่มี title, description, image, url
        this.tags = tags;
        this.injected = false;
    }
}

class OgMetaRemover {
    element(el) {
        const prop = (el.getAttribute('property') || '').toLowerCase();
        if (prop.startsWith('og:') || prop.startsWith('twitter:')) {
            el.remove();
        }
    }
}

class OgTagInserter {
    constructor(tags) { this.tags = tags; }
    element(el) {
        const t = this.tags;
        el.append([
            `<meta property="og:type" content="article" />`,
            `<meta property="og:site_name" content="${attrEsc(SITE_NAME)}" />`,
            `<meta property="og:locale" content="th_TH" />`,
            `<meta property="og:title" content="${attrEsc(t.title)}" />`,
            `<meta property="og:description" content="${attrEsc(t.description)}" />`,
            `<meta property="og:image" content="${attrEsc(t.image)}" />`,
            `<meta property="og:url" content="${attrEsc(t.url)}" />`,
            `<meta name="twitter:card" content="summary_large_image" />`,
            `<meta name="twitter:title" content="${attrEsc(t.title)}" />`,
            `<meta name="twitter:description" content="${attrEsc(t.description)}" />`,
            `<meta name="twitter:image" content="${attrEsc(t.image)}" />`,
        ].join('\n'), { html: true });
    }
}

export async function onRequest(context) {
    const { request, next } = context;
    const url = new URL(request.url);

    // 1. ตรวจว่าเป็นหน้า post เท่านั้น (ไม่ครอบ /create_post.html)
    const isPostPage = /^\/post(\.html)?$/.test(url.pathname);
    if (!isPostPage) return next();

    const postId = url.searchParams.get('id');
    if (!postId) return next();

    // 2. ถ้าไม่ใช่บอต — โหลดหน้า HTML ปกติโดยไม่เรียก API
    //    (ผู้ใช้จริงรับ HTML ก่อน JS ในหน้าค่อยโหลดข้อมูลเอง)
    if (!isCrawlerBot(request)) return next();

    // 3. โหลดหน้า HTML และดึงข้อมูลกระทู้พร้อมกัน
    const [response, postData] = await Promise.all([
        next(),
        fetchPostData(postId).catch(() => null),
    ]);

    // ถ้าดึงข้อมูลไม่ได้ ส่งหน้าเดิมไป
    if (!postData) return response;

    const tags = {
        title: attrEsc(`${postData.title} - ${SITE_NAME}`),
        description: makeDescription(postData.content),
        image: safeUrl(extractFirstImage(postData.content)) || FALLBACK_IMAGE,
        url: url.toString(),
    };

    // 4. ลบ og:* เดิม แล้วฉีดชุดใหม่ต่อท้าย <head>
    return new HTMLRewriter()
        .on('meta[property^="og:"], meta[property^="twitter:"], meta[name^="twitter:"]', new OgMetaRemover())
        .on('head', new OgTagInserter(tags))
        .transform(response);
}
