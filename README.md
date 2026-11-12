# Telegram Himoya boti

Telegram Business orqali akkaunt egasi tanlagan shaxsiy chatlardagi yangi xabarlarni kuzatadigan boshlang‘ich xavfsizlik boti.

## Nimalar ishlaydi

- Business akkaunt ulanishini qabul qiladi va ulanish ma’lumotlarini saqlaydi.
- Ruxsat berilgan shaxsiy chatlardagi yangi xabarlarni tekshiradi.
- `.apk` va ayrim ishga tushiriladigan fayllarni nomi/MIME turi bo‘yicha belgilaydi. Fayllarni yuklab olmaydi.
- Havolalarni matndan va Telegram message entity’laridan topadi.
- Qisqartirilgan havola, IP-manzilli domen, punycode va Telegram nomiga o‘xshatilgan domenlarni mahalliy qoidalar bilan baholaydi.
- Kod/parol so‘rash yoki shoshiltirishga o‘xshash ayrim o‘zbekcha/ruscha iboralarni aniqlaydi.
- Xavf belgisi topilganda akkaunt egasining Telegram bot chatiga ogohlantirish yuboradi.
- Pastki klaviaturadagi tugmalar orqali webhook holati, maslahatlar va bot yo‘riqnomasini ko‘rsatadi.
- Foydalanuvchi shubhali xabarni botga forward qilsa yoki havola, matn yoxud fayl yuborsa, qo‘lda mahalliy qoidalar bilan tekshiradi; xabarlarni saqlamaydi.
- Xabar matnini yoki fayllarni bazada saqlamaydi; tashqi skanerga yubormaydi.

## Muhim chegaralar

Bu versiya to‘liq antivirus emas. APK faylni **zararli** deb tasdiqlamaydi; uni tekshirilmagan ilova sifatida ogohlantiradi. Havola bahosi tarmoqda manzilni ochmasdan, mahalliy belgilar asosida beriladi. Keyinroq reputatsiya xizmati yoki hash tekshiruvi qo‘shilishi mumkin.

Bot faqat foydalanuvchi Telegram Business’da unga ochib bergan chatlardagi va ulanishdan keyin kelgan xabarlarni oladi. Chat tanlashda mavjud/yangi chatlar hamda kontaktlar/kontakt bo‘lmaganlarni tanlang. Maxfiy chatlar va ruxsat berilmagan suhbatlar botga kelmaydi. BotFather sozlamalarida Business Mode yoqilgan bo‘lishi kerak.

## O‘rnatish

1. `@BotFather` orqali bot yarating. BotFather’da botning **Business Mode** imkoniyatini yoqing.
2. `@BotFather` bergan tokenni hech kimga yubormang. `.env.example` faylidan `.env` nusxa oling va `BOT_TOKEN` qiymatiga tokenni kiriting.
3. Python 3.10 yoki undan yangi versiyani o‘rnating.
4. Terminalda loyiha papkasiga kirib:

   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # macOS/Linux:
   source .venv/bin/activate
   pip install -r requirements.txt
   python main.py
   ```

5. Telegram’da botni ochib `/start` bosing.
6. Telegram **Sozlamalar → Telegram Business → Chatbots** bo‘limida botni ulang. Barcha mavjud va yangi shaxsiy chatlar, kontaktlar va kontakt bo‘lmaganlarni tanlang; xabarlarni o‘qish ruxsatini bering.

Ulangandan so‘ng Telegram Business botga yangi xabarlar haqida `business_message` yangilanishlarini yuboradi. Render’da bot webhook orqali, kompyuterda ishga tushirganda esa long polling orqali oladi.

## Ishga tushirish muhiti

Botni doimiy ishlatish uchun pullik worker kerak bo‘ladi. Bepul Render web service’dan ham foydalanish mumkin, ammo servis 15 daqiqa kiruvchi so‘rov bo‘lmasa uxlaydi; keyingi so‘rovda uyg‘onishi taxminan bir daqiqa oladi. Shuning uchun xavfsizlik ogohlantirishlari kechikishi mumkin. Bepul servisning fayl tizimi doimiy emas, qayta ishga tushganda lokal baza yo‘qoladi. Bot ulanish ma’lumotini kerak bo‘lsa Telegram’dan qayta oladi.

### Render

Loyihada bepul Render web service uchun Blueprint (`render.yaml`) bor. GitHub repoga yuklangach, Render Dashboard’dan shu repoga Blueprint ulang. `BOT_TOKEN` va `WEBHOOK_SECRET` qiymatlarini maxfiy environment variable sifatida kiriting; `.env` faylini repoga joylamang. Render `RENDER_EXTERNAL_URL` va `PORT` qiymatlarini beradi, bot webhook’ni o‘zi sozlaydi. `WEBHOOK_SECRET` uchun terminalda `python -c "import secrets; print(secrets.token_urlsafe(32))"` buyrug‘i bilan tasodifiy qiymat yarating.

Render bepul rejasi doim uyg‘oq ishlash kafolatini bermaydi. Telegram webhook muvaffaqiyatsiz HTTP javobidan keyin yangilanishni bir necha bor qayta yuboradi, ammo Telegram ma’lum urinishlardan keyin yuborishni to‘xtatishi mumkin. Shu sabab bu sozlama bepul sinov va shaxsiy foydalanish uchun; xabarlarni darhol ogohlantirish zarur bo‘lsa, doimiy ishlaydigan pullik hosting tanlang.

## Ruxsatlar

Kerakli ruxsat — ruxsat berilgan chatlardagi xabarlarni o‘qish va biznes ulanish yangilanishlarini olish. Bot foydalanuvchi nomidan xabar yozish, xabar o‘chirish yoki profilni o‘zgartirish huquqlarini so‘ramaydi.
