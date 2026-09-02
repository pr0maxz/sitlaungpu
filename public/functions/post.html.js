// ไฟล์: /functions/post.html.js

export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const postId = url.searchParams.get('id');

    // 1. โหลดหน้าเว็บ post.html ต้นฉบับขึ้นมาก่อน
    const response = await env.ASSETS.fetch(request);

    // 2. ถ้าเข้าเว็บมาแบบไม่มี ID กระทู้ หรือไม่ใช่หน้า post ก็ปล่อยผ่านไปเลย
    if (!postId) {
        return response;
    }

    try {
        // 3. ยิงกระแสจิตไปดึงข้อมูลกระทู้จาก Backend API ของเรา
        const apiUrl = `https://my-backend.pr0maxz.workers.dev/api/posts/${postId}`;
        const apiRes = await fetch(apiUrl);
        
        if (!apiRes.ok) return response; // ถ้า API ขัดข้อง ก็ปล่อยหน้าเว็บเดิมออกไป
        
        const postData = await apiRes.json();
        
        // 4. เตรียมมวลสารสำหรับทำป้ายประกาศ (Open Graph Tags)
        const title = `${postData.title} - ศิษย์หลวงปู่`;
        
        // ตัดข้อความเนื้อหามาเป็นคำโปรยสัก 150 ตัวอักษร ลบแท็ก HTML ทิ้งให้หมด
        let cleanText = postData.content.replace(/<[^>]*>?/gm, '');
        const description = cleanText.length > 150 ? cleanText.substring(0, 150) + '...' : cleanText;
        
        // ถ้านิยายมีรูปภาพให้ดึงมาโชว์ ถ้าไม่มีให้ใช้โลโก้ของสำนักแทน
        const imageUrl = postData.image_url || "https://res.cloudinary.com/kjdb7wyp/image/upload/v1788019626/logo.png";
        const pageUrl = request.url;

        // 5. คาถา HTMLRewriter สำหรับสลักยันต์ Meta Tags ลงไปในส่วน <head> ของเว็บ
        class MetaTagInserter {
            element(element) {
                // เสก Meta Tags สำหรับ Facebook, LINE, Discord
                element.append(`<meta property="og:title" content="${title}" />`, { html: true });
                element.append(`<meta property="og:description" content="${description}" />`, { html: true });
                element.append(`<meta property="og:image" content="${imageUrl}" />`, { html: true });
                element.append(`<meta property="og:url" content="${pageUrl}" />`, { html: true });
                element.append(`<meta property="og:type" content="article" />`, { html: true });
                element.append(`<meta property="og:site_name" content="ศิษย์หลวงปู่" />`, { html: true });
                
                // เสก Meta Tags สำหรับ X (Twitter)
                element.append(`<meta name="twitter:card" content="summary_large_image" />`, { html: true });
                element.append(`<meta name="twitter:title" content="${title}" />`, { html: true });
                element.append(`<meta name="twitter:description" content="${description}" />`, { html: true });
                element.append(`<meta name="twitter:image" content="${imageUrl}" />`, { html: true });
            }
        }

        // แปลงร่างหน้าเว็บเก่า ยัดแท็กใหม่เข้าไป แล้วส่งให้เบราว์เซอร์หรือบอต
        return new HTMLRewriter()
            .on('head', new MetaTagInserter())
            .transform(response);

    } catch (error) {
        // อาถรรพ์ตีกลับ (Error) ให้ส่งหน้าเว็บเดิมไป ป้องกันเว็บพัง
        return response;
    }
}