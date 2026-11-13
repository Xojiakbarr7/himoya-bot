# Xavfsizlik va joylashtirish

## Ilovadagi himoyalar

- HTTPS webhook va kamida 32 belgili maxfiy kalit. Kalit tanada emas, sarlavhada tekshiriladi; noto‘g‘ri yoki takroriy sarlavha rad etiladi.
- Webhook tanasi 256 KiB bilan chegaralangan; o‘qish vaqti, navbat hajmi, JSON chuqurligi va Telegram maydonlari tekshiriladi. Siqilgan tanalar, takroriy JSON kalitlari va noto‘g‘ri JSON qabul qilinmaydi.
- Muvaffaqiyatli ishlangan update ID bazada 48 soat saqlanadi. Bir vaqtda takror kelgan webhooklar ketma-ket tekshiriladi. Jarayonning o‘rtasida uzilish bo‘lsa, ayrim tashqi amallar takrorlanishi mumkin; bu to‘liq exactly-once kafolati emas.
- Shaxsiy buyruqlar va tugmalar har bir foydalanuvchi uchun daqiqasiga 20 ta bilan cheklangan. Business/guruh himoyasi bu cheklov orqali tashlab yuborilmaydi.
- Sozlama tugmalari faqat foydalanuvchining o‘z bot chatida ishlaydi. Business ulanish egasi Telegram API orqali tasdiqlanadi.
- Telegram API so‘rovlari boshqa manzilga yo‘naltirilmaydi. Javob hajmi cheklangan; tarmoq xatosidagi tokenli URL logga chiqarilmaydi. Log formati token va webhook kalitini yashiradi. Production HTTP access loglari o‘chirilgan.
- SQLite fayli faqat server foydalanuvchisiga ochiq (0600); SQL qiymatlari parametr bilan beriladi. Baza xabar matni va fayllarni saqlamaydi.
- O‘chirilgan xabarlar rejimi faqat foydalanuvchi alohida yoqqanda yangi kiruvchi Business xabarlarining cheklangan matn nusxalarini RAM’da ushlaydi (1 soatgacha, 100 ta/ega, 2000 ta/jarayon). Media yuklab olinmaydi. Ko‘rish callbacklari egaga bog‘langan; rejimni o‘chirishda yoki ulanish o‘chirilganda egasining nusxalari tozalanadi. Fon tozalash har daqiqada ishlaydi. Bot chatiga allaqachon yuborilgan matnlar Telegram’da qoladi.
- aiohttp versiyasi belgilangan; Dependabot haftalik yangilanish PRlarini ochadi. Yangilanishlar tekshirilib, qo‘lda birlashtiriladi.

## Server egasi bajaradigan ishlar

1. Telegram, GitHub va Render hisoblarida 2FA/passkey yoqing, faol seanslar va hamkorlar ruxsatini tekshiring. Ilova kodi hisobingizdagi 2FA’ni o‘zi yoqa olmaydi.
2. BOT_TOKEN va WEBHOOK_SECRET faqat Render maxfiy environment sozlamalarida bo‘lsin. Ularni chatga, issue’ga yoki GitHub fayliga qo‘ymang. Webhook kaliti uchun `secrets.token_urlsafe(48)` kabi tasodifiy qiymat ishlating.
3. Token oshkor bo‘lsa BotFather orqali bekor qilib, yangisini Render’da o‘rnating; faqat GitHub faylidan o‘chirish yetmaydi. Webhook kalitini ham yangilang.
4. Keraksiz Telegram Business huquqlarini bermang. Avto o‘chirish uchun can_delete_all_messages, javob uchun can_reply yetarli; sovg‘a, Stars yoki profilni boshqarish huquqlari kerak emas.
5. Render servisining health check yo‘lini /healthz qiling. Blueprint yangi servislar uchun shu yo‘lni belgilaydi.

## Saqlash va cheklovlar

Render Free lokal fayl tizimi doimiy emas. Deploy/restartda lokal SQLite yo‘qolishi, foydalanuvchi rejimlari boshlang‘ich holatga qaytishi va takrorlarni eslab qolish ma’lumoti o‘chishi mumkin. Doimiy saqlash uchun doimiy disk yoki tashqi baza zarur; ushbu yangilanish pullik servis yaratmaydi va tashqi bazani avtomatik ulamaydi.

Bu himoyalar trafikni butunlay to‘sadigan DDoS xizmati emas. Server, hosting, hisoblar yoki oshkor bo‘lgan token nazorati buzilsa, ilova kodi buning o‘rnini bosa olmaydi. Fayllar antivirus kabi tahlil qilinmaydi.

## Tekshirish

`python -m unittest -v test_security`

Sinovlar mahalliy HTTP server va soxta Telegram API bilan ishlaydi; haqiqiy foydalanuvchi xabarlari yuborilmaydi va o‘chirilmaydi.
