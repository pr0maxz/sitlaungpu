export async function onRequest(context) {
    const { request, next } = context;
    const url = new URL(request.url);

    // 1. ให้ Cloudflare โหลดหน้าเว็บ HTML สดๆ ออกมาก่อน
    const response = await next();

    // 2. ตรวจสอบว่าใช่ลิงก์ของหน้า post หรือไม่ (ครอบคลุมทั้ง /post และ /post.html)
    if (url.pathname.includes('/post')) {
        const postId = url.searchParams.get('id');
        if (!postId) return response; // ถ้าไม่มี id กระทู้ ก็ปล่อยผ่านไป

        try {
            // 3. ยิง API ไปดึงข้อมูลกระทู้จากหลังบ้าน
            const apiRes = await fetch(`https://my-backend.pr0maxz.workers.dev/api/posts/${postId}`);
            if (!apiRes.ok) return response;
            
            const postData = await apiRes.json();
            const title = `${postData.title} - ศิษย์หลวงปู่`;
            
            // ล้างแท็ก HTML ออกจากเนื้อหาเพื่อทำคำโปรย
            let cleanText = postData.content.replace(/<[^>]*>?/gm, '').trim();
            const description = cleanText.length > 120 ? cleanText.substring(0, 120) + '...' : cleanText;
            
            // 4. หารูปแรกในกระทู้ (ถ้ามี) ถ้าไม่มีให้ใช้รูปโลโก้สำนักแทน
            const imgMatch = postData.content.match(/<img[^>]+src=["']([^"']+)["']/i);
            const imageUrl = imgMatch ? imgMatch[1] : "https://res.cloudinary.com/kjdb7wyp/image/upload/v1788019626/logo.png";

            // 5. เสก Meta Tags ยัดเข้าไปใน <head> สดๆ เพื่อส่งให้บอต Facebook อ่าน
            class MetaTagInserter {
                element(e) {
                    e.append(`<meta property="og:title" content="${title}" />`, { html: true });
                    e.append(`<meta property="og:description" content="${description}" />`, { html: true });
                    e.append(`<meta property="og:image" content="${imageUrl}" />`, { html: true });
                    e.append(`<meta property="og:url" content="${request.url}" />`, { html: true });
                    e.append(`<meta property="og:type" content="article" />`, { html: true });
                }
            }

            return new HTMLRewriter().on('head', new MetaTagInserter()).transform(response);
        } catch (err) {
            return response; // อาถรรพ์ตีกลับ (Error) ให้ส่งหน้าเว็บปกติไป ปลอดภัยไว้ก่อน
        }
    }

    // หน้าอื่นๆ ปล่อยผ่านตามปกติ
    return response;
}