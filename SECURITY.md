# Xavfsizlik va joylashtirish

## Ilovadagi himoyalar

- HTTPS webhook va kamida 32 belgili maxfiy kalit. Kalit tanada emas, sarlavhada tekshiriladi; noto‘g‘ri yoki takroriy sarlavha rad etiladi.
- Webhook tanasi 256 KiB bilan chegaralangan; o‘qish vaqti, navbat hajmi, JSON chuqurligi va Telegram maydonlari tekshiriladi. Siqilgan tanalar, takroriy JSON kalitlari va noto‘g‘ri JSON qabul qilinmaydi.
- Muvaffaqiyatli ishlangan update ID bazada 48 soat saqlanadi. Bir vaqtda takror kelgan webhooklar ketma-ket tekshiriladi. Jarayonning o‘rtasida uzilish bo‘lsa, ayrim tashqi amallar takrorlanishi mumkin; bu to‘liq exactly-once kafolati emas.
- Shaxsiy buyruqlar va tugmalar har bir foydalanuvchi uchun daqiqasiga 20 ta bilan cheklangan. Business/guruh himoyasi bu cheklov orqali tashlab yuborilmaydi.
- Sozlama tugmalari faqat foydalanuvchining o‘z bot chatida ishlaydi. Business ulanish egasi Telegram API orqali tasdiqlanadi.
- Telegram API so‘rovlari boshqa manzilga yo‘naltirilmaydi. Javob hajmi cheklangan; tarmoq xatosidagi tokenli URL logga chiqarilmaydi. Log formati token va webhook kalitini yashiradi. Production HTTP access loglari o‘chirilgan.
- SQLite fayli faqat server foydalanuvchisiga ochiq (0600); SQL qiymatlari parametr bilan beriladi. Baza xabar matni va fayllarni saqlamaydi.
- O‘chirilgan xabarlar rejimi faqat rozilik bilan yoqiladi: matn va oddiy Telegram media file_id saqlanadi (72 soat; o‘chirish aniqlansa yana 72 soat; 1000/ega, 20000/jami). HISTORY_DATABASE_URL bilan PostgreSQL/TLS, aks holda RAM. Media yuklab olinmaydi; himoyalangan, pulli va bir martalik media arxivlanmaydi. Faqat egasi ko‘radi. Rejim o‘chirilganda yoki ulanish bekor qilinganda nusxalar tozalanadi. Muddati tugagan yozuvlarni ko‘rish taqiqlanadi; fon tozalash server ishlaganda har daqiqada. Bot chatiga yuborilgan nusxalar u yerda qoladi.
- aiohttp versiyasi belgilangan; Dependabot haftalik yangilanish PRlarini ochadi. Yangilanishlar tekshirilib, qo‘lda birlashtiriladi.
- Phishing.Database domenlar ro‘yxati faqat belgilangan HTTPS manbadan yuklanadi (24 MB chegarasi, yo‘naltirishlarsiz). Foydalanuvchining URL’i va xabar matni tashqi bazaga yuborilmaydi. Faqat aniq domen mosligi ishlatiladi; ota domen/subdomen avtomatik aybdor deb olinmaydi. Eskirgan baza holati ko‘rsatiladi, 7 kundan eski nusxa hukm chiqarish uchun ishlatilmaydi.
- APK chuqur tekshiruvi faqat botga qo‘lda yuborilgan fayl va egasining alohida rozilik tugmasi orqali ishlaydi. Token 15 daqiqa amal qiladi, egaga bog‘langan va bir marta ishlatiladi. 20 MB yuklash chegarasi, 2 MB manifest, 10000 ZIP yozuvi, bitta parallel skan va soatiga 3 ta so‘rov chegarasi bor. Fayl RAM’da ko‘riladi, ishga tushirilmaydi, diskka chiqarilmaydi va arxiv ochib fayl tizimiga yozilmaydi.
- VirusTotal ixtiyoriy: VIRUSTOTAL_API_KEY berilsa, faqat SHA-256 orqali mavjud hisobot olinadi. Faylning o‘zi yoki chat matni yuborilmaydi. 404/limit/uzilish hech qachon “xavfsiz” hukmiga aylantirilmaydi. API kaliti logda yashiriladi. Ruxsatlar xavfli imkoniyatlarni bildiradi, virusni isbotlamaydi.
- 100 MB APK yuklash faqat bot bergan, 256 bit tasodifiy va 15 daqiqalik bir martalik havola orqali bajariladi. Tekshiruv natijasi token yaratilgan akkauntga yuboriladi; brauzer owner ID tanlay olmaydi. POST’da Origin, yagona token sarlavhasi, rozilik, content type, encoding va oqim hajmi tekshiriladi. Webhook’ning 256 KiB chegarasi oshirilmaydi. Havolalar maxfiy hisoblanadi va logga yozilmaydi. Sahifa nonce-CSP, no-store va no-referrer bilan beriladi.
- Katta APK yuklashda anonim `TemporaryFile` ishlatiladi; diskka arxiv ichidagi fayllar chiqarilmaydi va hech narsa bajarilmaydi. Tekshiruv uchun fayl 64 KiB bo‘laklarda xeshlanadi. Vaqtinchalik fayl muvaffaqiyat, xato va bekor qilishda yopiladi. Yuklash 300 soniya, har o‘qish 30 soniya bilan cheklangan. Kiruvchi yuklashlar soni va navbat chegaralangan.

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
