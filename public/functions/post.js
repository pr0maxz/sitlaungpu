export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const postId = url.searchParams.get('id');

    // 1. โหลดหน้าเว็บ post.html ต้นฉบับมาเตรียมไว้
    const response = await env.ASSETS.fetch(request);

    // 2. ถ้าไม่มี ID กระทู้ ให้ปล่อยผ่าน
    if (!postId) {
        return response;
    }

    try {
        // 3. ยิงไปดึงข้อมูลกระทู้จาก Backend
        const apiUrl = `https://my-backend.pr0maxz.workers.dev/api/posts/${postId}`;
        const apiRes = await fetch(apiUrl);
        
        if (!apiRes.ok) return response;
        
        const postData = await apiRes.json();
        
        // 4. เตรียมข้อมูลสำหรับ Meta Tags
        const title = `${postData.title} - ศิษย์หลวงปู่`;
        
        // 4.1 ล้างแท็ก HTML ออกเพื่อทำคำโปรย (Description)
        let cleanText = postData.content.replace(/<[^>]*>?/gm, '').trim();
        const description = cleanText.length > 120 ? cleanText.substring(0, 120) + '...' : cleanText;
        
        // 4.2 ค้นหารูปภาพแรกสุดที่อยู่ในเนื้อหา (content) เพื่อเอามาทำรูปปก
        const imgMatch = postData.content.match(/<img[^>]+src=["']([^"']+)["']/i);
        // ถ้าระบบเจอรูปในเนื้อหาให้ใช้รูปนั้น ถ้าไม่เจอให้ใช้โลโก้สำนัก
        const imageUrl = imgMatch ? imgMatch[1] : "https://res.cloudinary.com/kjdb7wyp/image/upload/v1788019626/logo.png";
        
        const pageUrl = request.url;

        // 5. คาถา HTMLRewriter สำหรับสลักยันต์ Meta Tags ลงไปในส่วน <head> เพื่อหลอกบอต Facebook
        class MetaTagInserter {
            element(element) {
                element.append(`<meta property="og:title" content="${title}" />`, { html: true });
                element.append(`<meta property="og:description" content="${description}" />`, { html: true });
                element.append(`<meta property="og:image" content="${imageUrl}" />`, { html: true });
                element.append(`<meta property="og:url" content="${pageUrl}" />`, { html: true });
                element.append(`<meta property="og:type" content="article" />`, { html: true });
                element.append(`<meta property="og:site_name" content="ศิษย์หลวงปู่" />`, { html: true });
                
                element.append(`<meta name="twitter:card" content="summary_large_image" />`, { html: true });
                element.append(`<meta name="twitter:title" content="${title}" />`, { html: true });
                element.append(`<meta name="twitter:description" content="${description}" />`, { html: true });
                element.append(`<meta name="twitter:image" content="${imageUrl}" />`, { html: true });
            }
        }

        // แปลงร่างหน้าเว็บเก่า ยัดแท็กใหม่เข้าไป แล้วส่งให้บอต
        return new HTMLRewriter()
            .on('head', new MetaTagInserter())
            .transform(response);

    } catch (error) {
        // หากมีอะไรผิดพลาด ให้ส่งหน้าเว็บเดิมกลับไป ป้องกันเว็บพัง
        return response;
    }
}