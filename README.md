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
- Pastki menyudagi **🗑 Avto o‘chirish sozlamasi** orqali foydalanuvchi Business shaxsiy chatlaridagi zararli xabarlarni avtomatik o‘chirishni yoqishi yoki o‘chirishi mumkin; standart holati o‘chiq.
- Rejim yoqilganida APK/ishga tushiriladigan fayllar hamda barcha havolali kiruvchi xabarlar o‘chiriladi. Oddiy, qisqartirilgan va matn ichiga yashirilgan havolalar, shuningdek media izohidagi havolalar ham aniqlanadi. Faqat matnli ogohlantirish iboralari avtomatik o‘chirilmaydi. O‘chirilgan xabar haqida egasiga bot orqali xabar boradi.
- Pastki menyudagi **⚠️ Yuborilgan xabar ogohlantirishi** orqali egasi akkauntidan APK yoki aniq shubhali havola yuborilganda oluvchiga ogohlantirish yozishni yoqish/o‘chirish mumkin; standart holati o‘chiq.
- Pastki menyudagi **🌍 Xalqaro raqam ogohlantirishi** xabarda ochiq yozilgan/kontakt sifatida yuborilgan `+998` yoki `+7`dan boshqa xalqaro raqamni aniqlasa bir marta ogohlantiradi. Yangi yuboruvchi uchun alohida bildirishnoma yuborilmaydi.
- Pastki klaviaturadagi tugmalar orqali webhook holati, maslahatlar va bot yo‘riqnomasini ko‘rsatadi.
- Foydalanuvchi shubhali xabarni botga forward qilsa yoki havola, matn yoxud fayl yuborsa, qo‘lda mahalliy qoidalar bilan tekshiradi; xabarlarni saqlamaydi.
- Guruhda APK, ishga tushiriladigan fayl, istalgan havola yoki belgilangan firibgarlik iborasi topilsa, xabarni o‘chiradi va guruhga kim hamda nima yuborganini yozadi.
- Xabar matnini yoki fayllarni bazada saqlamaydi; tashqi skanerga yubormaydi.

## Muhim chegaralar

Bu versiya to‘liq antivirus emas. APK faylni **zararli** deb tasdiqlamaydi; uni tekshirilmagan ilova sifatida ogohlantiradi. Havola bahosi tarmoqda manzilni ochmasdan, mahalliy belgilar asosida beriladi. Keyinroq reputatsiya xizmati yoki hash tekshiruvi qo‘shilishi mumkin.

Bot faqat foydalanuvchi Telegram Business’da unga ochib bergan chatlardagi va ulanishdan keyin kelgan xabarlarni oladi. Chat tanlashda mavjud/yangi chatlar hamda kontaktlar/kontakt bo‘lmaganlarni tanlang. Maxfiy chatlar va ruxsat berilmagan suhbatlar botga kelmaydi. BotFather sozlamalarida Business Mode yoqilgan bo‘lishi kerak.

Yuborilgan xabar ogohlantirishi Telegram Business’dagi **Javob berish** ruxsati va chat cheklovlariga bog‘liq; ayrim chatlarda Telegram javob yuborishni rad etishi mumkin. Avto o‘chirish rejimi esa faqat **barcha xabarlarni o‘chirish** huquqi berilganida ishlaydi. Bot shubhali belgilarni taxminiy aniqlaydi; APK’ni antivirus kabi tekshirmaydi.

Shaxsiy chatlarda avto o‘chirishni yoqish uchun botda **🗑 Avto o‘chirish sozlamasi → ✅ Yoqish** tugmasini bosing. Telegram Business → Chatbots sozlamasida **barcha xabarlarni o‘chirish** huquqini yoqing. Huquq berilmasa, bot xabarni o‘chira olmaydi va sizga ruxsat yetishmayotgani haqida xabar beradi. Bu sozlama guruh moderatsiyasiga ta’sir qilmaydi.

Yuborilgan xabar ostiga ogohlantirish yozish uchun **⚠️ Yuborilgan xabar ogohlantirishi → ✅ Yoqish**ni tanlang va Telegram Business’da **Javob berish** huquqini bering. Telegram ayrim chatlarda xabar yuborishni cheklashi mumkin.

Xalqaro raqam ogohlantirishi **🌍 Xalqaro raqam ogohlantirishi** tugmasi orqali boshqariladi. Telegram Bot API odatda yuboruvchining yashirin telefon raqamini botga bermaydi. Shu sabab faqat xabarda `+` bilan ochiq yozilgan raqamlar yoki yuborilgan kontaktning raqami tekshiriladi. Kontakt boshqa odamga tegishli bo‘lishi mumkin. Raqamning o‘zi bazada saqlanmaydi.

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
6. Telegram **Sozlamalar → Telegram Business → Chatbots** bo‘limida botni ulang. Kerakli shaxsiy chatlarni tanlang; xabarlarni o‘qish va avto o‘chirishni ishlatmoqchi bo‘lsangiz, barcha xabarlarni o‘chirish ruxsatini bering.

Ulangandan so‘ng Telegram Business botga yangi xabarlar haqida `business_message` yangilanishlarini yuboradi. Render’da bot webhook orqali, kompyuterda ishga tushirganda esa long polling orqali oladi.

## Ishga tushirish muhiti

Botni doimiy ishlatish uchun pullik worker kerak bo‘ladi. Bepul Render web service’dan ham foydalanish mumkin, ammo servis 15 daqiqa kiruvchi so‘rov bo‘lmasa uxlaydi; keyingi so‘rovda uyg‘onishi taxminan bir daqiqa oladi. Shuning uchun xavfsizlik ogohlantirishlari kechikishi mumkin. Bepul servisning fayl tizimi doimiy emas, qayta ishga tushganda lokal baza yo‘qoladi. Bot ulanish ma’lumotini kerak bo‘lsa Telegram’dan qayta oladi.

### Render

Loyihada bepul Render web service uchun Blueprint (`render.yaml`) bor. GitHub repoga yuklangach, Render Dashboard’dan shu repoga Blueprint ulang. `BOT_TOKEN` va `WEBHOOK_SECRET` qiymatlarini maxfiy environment variable sifatida kiriting; `.env` faylini repoga joylamang. Render `RENDER_EXTERNAL_URL` va `PORT` qiymatlarini beradi, bot webhook’ni o‘zi sozlaydi. `WEBHOOK_SECRET` uchun terminalda `python -c "import secrets; print(secrets.token_urlsafe(48))"` buyrug‘i bilan tasodifiy qiymat yarating.

Render bepul rejasi doim uyg‘oq ishlash kafolatini bermaydi. Telegram webhook muvaffaqiyatsiz HTTP javobidan keyin yangilanishni bir necha bor qayta yuboradi, ammo Telegram ma’lum urinishlardan keyin yuborishni to‘xtatishi mumkin. Shu sabab bu sozlama bepul sinov va shaxsiy foydalanish uchun; xabarlarni darhol ogohlantirish zarur bo‘lsa, doimiy ishlaydigan pullik hosting tanlang.

## Ruxsatlar

Avto o‘chirish uchun Telegram Business’dagi `can_delete_all_messages`, yuborilgan xabar ogohlantirishi uchun `can_reply` huquqi kerak. Ikkala sozlama ham foydalanuvchi tanloviga ko‘ra saqlanadi va standart holatda o‘chiq turadi. Render bepul servisining fayl tizimi doimiy emasligi sabab qayta deploydan keyin sozlamalarni yana tekshirib, kerak bo‘lsa qayta yoqing.

## Xavfsizlik

Webhook autentifikatsiyasi, kiruvchi ma’lumot tekshiruvi, takrorlarni bloklash, shaxsiy spam cheklovi va maxfiy log formati qo‘shilgan. To‘liq amaliy ko‘rsatma va hosting cheklovlari: [SECURITY.md](SECURITY.md).

Sinov: `python -m unittest -v test_security`.

## Ikki akkaunt roziligi bilan bitta rasm sinovi

**🧪 O‘z rasmlarimni sinash** tugmasi odatda o‘chiq bo‘lgan, 15 daqiqalik bitta rasm sinovini yaratadi. Bot Telegram Business orqali qabul qiluvchi akkauntga ulangan bo‘lishi kerak. Qabul qiluvchi sinov havolasini o‘zining ikkinchi akkauntida ochadi va yuboruvchi akkaunt alohida **Roziman**ni bosadi. Faqat shundan keyin shu yuboruvchidan kelgan bitta `photo` xabari Telegram API qayta ishlatishga ruxsat bergan `file_id` bilan egasining bot chatiga nusxalanadi. Fayl yuklab olinmaydi, `file_id` bazada saqlanmaydi; taklif tokenining faqat xeshi va rozilik holati saqlanadi.

Bu bir martalik rasmlarni ochish yoki ularning himoyasini chetlab o‘tish mexanizmi emas. Telegram bunday rasmni botga `photo/file_id` ko‘rinishida bermasa yoki qayta yuborishni rad etsa, nusxa yuborilmaydi. Haqiqiy bir martalik rasm bilan ishlashi tasdiqlanmagan. Sinov mantiqi soxta Telegram API bilan tekshirilgan. Birinchi oddiy rasm ham sinov kvotasini ishlatadi. Ikkala akkaunt ham **Sinovni to‘xtatish** orqali o‘z roziligini bekor qilishi mumkin. Server qayta deploy bo‘lsa lokal bazadagi sinov bekor bo‘lishi mumkin.
