```txt
npm install
npm run dev
```

```txt
npm run deploy
```

## ตั้งค่าความปลอดภัยก่อน deploy

ตั้งค่า origin ของหน้า Pages ที่อนุญาตให้เรียก API โดยระบุให้ครบทุกโดเมนที่ใช้งานจริง (คั่นด้วย comma):

```txt
wrangler secret put JWT_SECRET
wrangler secret put TURNSTILE_SECRET
wrangler deploy --var ALLOWED_ORIGINS:https://sitluangpu.pages.dev
```

- ห้ามนำ `schema.sql` เวอร์ชันก่อนหน้านี้ที่สร้างบัญชี `ADMIN` แบบตายตัวกลับมาใช้
- ฐานข้อมูลที่ deploy อยู่แล้วต้องเปลี่ยนรหัสผ่านผู้ดูแล และหมุน `JWT_SECRET` ด้วยตนเองทันที; การแก้ไฟล์ schema ไม่เปลี่ยนข้อมูลเดิม
- หากใช้ custom domain ให้เพิ่มโดเมนนั้นใน `ALLOWED_ORIGINS` ก่อน deploy ไม่เช่นนั้น browser จะเรียก API ไม่ได้

## Session แบบ HttpOnly cookie

หลัง deploy เวอร์ชันนี้ ผู้ใช้ทุกคนต้องเข้าสู่ระบบใหม่หนึ่งครั้ง ระบบจะเก็บ session ใน cookie ที่ JavaScript อ่านไม่ได้ แทนการเก็บ JWT ใน `localStorage`.

ขณะ API ยังอยู่บน `workers.dev` และหน้าเว็บอยู่บน `pages.dev` ต้องเปิดใช้ cookie ข้าม site (`SameSite=None`) เพื่อให้ทำงานได้. สำหรับการป้องกันระยะยาว ควรผูก API กับ custom domain ที่อยู่ site เดียวกับหน้าเว็บ เช่น `api.example.com` และ `www.example.com`.

[For generating/synchronizing types based on your Worker configuration run](https://developers.cloudflare.com/workers/wrangler/commands/#types):

```txt
npm run cf-typegen
```

Pass the `CloudflareBindings` as generics when instantiating `Hono`:

```ts
// src/index.ts
const app = new Hono<{ Bindings: CloudflareBindings }>()
```
