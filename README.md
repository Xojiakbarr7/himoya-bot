# Telegram Himoya boti

Telegram Business orqali akkaunt egasi tanlagan shaxsiy chatlardagi yangi xabarlarni kuzatadigan boshlang‘ich xavfsizlik boti.

## Nimalar ishlaydi

- Business akkaunt ulanishini qabul qiladi va ulanish ma’lumotlarini saqlaydi.
- Ruxsat berilgan shaxsiy chatlardagi kiruvchi va egasi yuborgan xabarlarni tekshiradi.
- `.apk` va ayrim ishga tushiriladigan fayllarni nomi/MIME turi bo‘yicha belgilaydi. Fayllarni yuklab olmaydi.
- Havolalarni matndan va Telegram message entity’laridan topadi.
- Qisqartirilgan havola, IP-manzilli domen, punycode va Telegram nomiga o‘xshatilgan domenlarni mahalliy qoidalar bilan baholaydi.
- Kod/parol so‘rash yoki shoshiltirishga o‘xshash ayrim o‘zbekcha/ruscha iboralarni aniqlaydi.
- Xavf belgisi topilganda akkaunt egasining Telegram bot chatiga ogohlantirish yuboradi.
- Egasi akkauntidan APK, havola yoki shubhali ibora yuborilsa, o‘sha xabar ostiga javob qilib oluvchini ogohlantiradi. Oddiy xabarlarning ostiga ogohlantirish qo‘shmaydi.
- Pastki klaviaturadagi tugmalar orqali webhook holati, maslahatlar va bot yo‘riqnomasini ko‘rsatadi.
- Foydalanuvchi shubhali xabarni botga forward qilsa yoki havola, matn yoxud fayl yuborsa, qo‘lda mahalliy qoidalar bilan tekshiradi; xabarlarni saqlamaydi.
- Guruhda APK, ishga tushiriladigan fayl, istalgan havola yoki belgilangan firibgarlik iborasi topilsa, xabarni o‘chiradi va guruhga kim hamda nima yuborganini yozadi.
- Xabar matnini yoki fayllarni bazada saqlamaydi; tashqi skanerga yubormaydi.

## Muhim chegaralar

Bu versiya to‘liq antivirus emas. APK faylni **zararli** deb tasdiqlamaydi; uni tekshirilmagan ilova sifatida ogohlantiradi. Havola bahosi tarmoqda manzilni ochmasdan, mahalliy belgilar asosida beriladi. Keyinroq reputatsiya xizmati yoki hash tekshiruvi qo‘shilishi mumkin.

Bot faqat foydalanuvchi Telegram Business’da unga ochib bergan chatlardagi va ulanishdan keyin kelgan xabarlarni oladi. Chat tanlashda mavjud/yangi chatlar hamda kontaktlar/kontakt bo‘lmaganlarni tanlang. Maxfiy chatlar va ruxsat berilmagan suhbatlar botga kelmaydi. BotFather sozlamalarida Business Mode yoqilgan bo‘lishi kerak.

Egasi yuborgan shubhali xabar ostiga oluvchiga javob yozish uchun Telegram Business’da botga xabarlarni o‘qish bilan birga **Reply / Javob berish** huquqini ham bering. Telegram bu javobni ayrim shaxsiy chatlarda, yaqinda kiruvchi xabar bo‘lganida va ulanish ruxsatlari yetarli bo‘lganda qabul qiladi. Huquq yoki Telegram cheklovi bo‘lsa, ogohlantirish yuborilmasligi mumkin. Bot shubhali belgilarni taxminiy aniqlaydi; APK’ni antivirus kabi tekshirmaydi.

### Guruh moderatsiyasi

BotFather’da bot uchun guruhlarga qo‘shishga ruxsat bering (**Allow Groups**). Botni guruhga qo‘shib, administrator qiling va **Delete Messages** huquqini bering. Admin botlar guruh xabarlarini oladi; oddiy a’zo bo‘lsa, Telegram maxfiylik rejimi sabab barcha xabarlarni ko‘rmasligi mumkin. Bot har qanday havolani o‘chiradi, shu jumladan xavfsiz havolalarni ham. APK va ishga tushadigan fayllar esa fayl turi bo‘yicha belgilanadi — ichidagi kod tahlil qilinmaydi. O‘chirish muvaffaqiyatli bo‘lgandan keyin guruhga yuboruvchi va sabab ko‘rsatilgan xabar yoziladi. Telegram Bot API xabarni faqat yuborilganidan keyingi 48 soat ichida o‘chirishga ruxsat beradi; bu bot xabarlarni kelishi bilan tekshiradi.

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

Kerakli ruxsatlar — ruxsat berilgan chatlardagi xabarlarni o‘qish, biznes ulanish yangilanishlarini olish va shubhali xabarga javob berish. Javob huquqi oddiy xabarlarni jo‘natish uchun ishlatilmaydi; faqat xavf belgisi topilgan egasi yuborgan xabar ostiga ogohlantirish qo‘yiladi.
