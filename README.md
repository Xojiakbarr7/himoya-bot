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
- Pastki klaviaturadagi tugmalar orqali webhook holati, maslahatlar va bot yo‘riqnomasini ko‘rsatadi.
- **🛡 Xavfsizlik markazi** — Business ulanishi va himoya rejimlari holati, so‘nggi 7 kun hisoboti hamda chatlar bo‘yicha xavf hodisalarini ko‘rsatadi. Hisobotda xabar matni, fayl yoki to‘liq havola saqlanmaydi; faqat egaga tegishli chat yorlig‘i, hodisa turi, amal va xavf bahosi saqlanadi. Hisobot yozuvlari 30 kundan keyin o‘chiriladi.
- **📝 O‘chirilgan xabarlar** — foydalanuvchi alohida rozilik bilan yoqsa, Business shaxsiy chatlaridagi oxirgi 1000 tagacha kiruvchi xabarning matni va oddiy media identifikatorini 72 soatgacha eslab turadi. `deleted_business_messages` hodisasi kelsa, oldindan ko‘rilgan matnni faqat akkaunt egasiga ko‘rsatadi. Rejim standart holatda o‘chiq.
- Foydalanuvchi shubhali xabarni botga forward qilsa yoki havola, matn yoxud fayl yuborsa, qo‘lda mahalliy qoidalar bilan tekshiradi; qo‘lda tekshirilgan xabarlar tarixga yozilmaydi.
- Guruhda APK, ishga tushiriladigan fayl, istalgan havola yoki belgilangan firibgarlik iborasi topilsa, xabarni o‘chiradi va guruhga kim hamda nima yuborganini yozadi.
- Tarix yoqilganda matn va media identifikatori saqlanadi; fayllar yuklab olinmaydi va tashqi skanerga yuborilmaydi.

Xavfsizlik markazi hisobotlari o‘chirilgan xabarlar tarixidan mustaqil: xavf aniqlanganda hodisa metama’lumoti qayd qilinadi, xabar matni yoki to‘liq havola esa hisobotga yozilmaydi. PostgreSQL ulangan bo‘lsa, hisobotlar bazada saqlanadi; u ulanmagan bo‘lsa, hisobotlar lokal server bazasida saqlanib, restartdan keyin yo‘qolishi mumkin.

## O‘chirilgan xabarlarni vaqtincha ko‘rish

Pastdagi **📝 O‘chirilgan xabarlar → Roziman, yoqish** orqali ishga tushiriladi. Faqat botga ruxsat berilgan shaxsiy Business chatlaridan keladigan yangi kiruvchi xabarlar eslab turiladi. Sozlama yoqilmasdan oldingi yoki botga umuman kelmagan xabarlar tiklanmaydi. Telegram o‘chirish hodisasida xabar matnini hamda kim o‘chirganini yubormaydi; butun chatni o‘chirish har doim shu hodisani keltirib chiqarmasligi mumkin.

Tarix muddati — qabul qilingandan boshlab 72 soat. O‘chirish hodisasi aniqlansa yana 72 soat beriladi. Har egaga 1000, butun botga 20000 yozuv chegarasi bor: to‘lsa eng eski yozuvlar oldinroq o‘chadi. Matn/caption, rasm, video, ovozli xabar, audio, hujjat, GIF, video doira va stiker qo‘llanadi. Media uchun faqat Telegram `file_id` saqlanadi; faylning o‘zi yuklab olinmaydi. Qayta ko‘rish Telegram faylni qayta yuborishga ruxsat berishiga bog‘liq. Bir martalik, himoyalangan yoki pulli media arxivlanmaydi. Kontakt, lokatsiya va so‘rovnomalar bu versiyaga kirmaydi.

`HISTORY_DATABASE_URL` berilsa, tarix va uning yoqish/o‘chirish sozlamasi TLS orqali tashqi PostgreSQL’da saqlanadi va Render restartidan keyin qoladi. URL berilmasa RAM rejimi ishlaydi: restartda tarix yo‘qoladi. Menyu bu holatni ochiq ko‘rsatadi. Muddati tugagan yozuvlar ko‘rsatilmaydi, ishlayotgan server har daqiqada tozalaydi; server/baza o‘chiq bo‘lsa fizik tozalash qayta ishlaganda davom etadi. Baza nosoz bo‘lsa Telegram update qayta urinishi uchun vaqtinchalik xato qaytariladi.

### Bepul tashqi bazani ulash (Neon)

1. https://console.neon.tech da Free loyiha oching. Boshqa loyiha bazasini ishlatmang.
2. `Connect` bo‘limidan PostgreSQL connection URL nusxalang (TLS yoqilgan bo‘lsin).
3. Render → himoya-bot → Environment: `HISTORY_DATABASE_URL` qiymatiga URL qo‘ying va saqlab deploy qiling. Parol/URL’ni chatga yoki GitHubga yozmang.
4. Botdagi **O‘chirilgan xabarlar** menyusida **Tashqi baza ulangan** holatini tekshiring, rejimni qayta yoqing.
5. Ikkinchi akkauntdan oddiy matn/rasm yuboring, o‘chiring, botda ko‘ring. Restartdan so‘ng ham ro‘yxatni tekshiring.

Baza ulanganda jadvallar avtomatik yaratiladi (`qalqon_history`, `qalqon_history_settings`). Oldingi RAM nusxalari avtomatik ko‘chirilmaydi. Provider kvotalari va tariflari alohida amal qiladi. Bu versiya uchun tashqi baza hali provision qilinmagan: jonli PostgreSQL integratsiya testi URL qo‘shilgandan keyin bajariladi.

O‘chirish hodisasidan so‘ng bot bildirishnoma yuboradi; **Xabarlarni ko‘rish** yoki rejim menyusidagi **O‘chirilganlarni ko‘rish** orqali varaqlanadi. Spamni kamaytirish uchun bir egaga daqiqasiga 6 tagacha o‘chirish bildirishnomasi yuboriladi; ortiqcha hodisalarda ham matnlar cheklovlar doirasida ro‘yxatda ko‘rinadi. Botning o‘zi avto o‘chirgan xabarlari ikkinchi marta bu bildirishnomaga kiritilmaydi.

**O‘chirish** yoki **Vaqtinchalik xotirani tozalash** egasining saqlangan nusxalarini o‘chiradi. Bot allaqachon egasining Telegram chatiga yuborgan matnlar o‘sha chatda qoladi. Har bir egaga faqat o‘z yozuvlari ochiladi; callback token boshqa egaga matnni ko‘rsatmaydi.

## Muhim chegaralar

Bu versiya to‘liq antivirus emas. APK faylni **zararli** deb tasdiqlamaydi; uni tekshirilmagan ilova sifatida ogohlantiradi. Havola bahosi tarmoqda manzilni ochmasdan, mahalliy belgilar asosida beriladi. Keyinroq reputatsiya xizmati yoki hash tekshiruvi qo‘shilishi mumkin.

Bot faqat foydalanuvchi Telegram Business’da unga ochib bergan chatlardagi va ulanishdan keyin kelgan xabarlarni oladi. Chat tanlashda mavjud/yangi chatlar hamda kontaktlar/kontakt bo‘lmaganlarni tanlang. Maxfiy chatlar va ruxsat berilmagan suhbatlar botga kelmaydi. BotFather sozlamalarida Business Mode yoqilgan bo‘lishi kerak.

Yuborilgan xabar ogohlantirishi Telegram Business’dagi **Javob berish** ruxsati va chat cheklovlariga bog‘liq; ayrim chatlarda Telegram javob yuborishni rad etishi mumkin. Avto o‘chirish rejimi esa faqat **barcha xabarlarni o‘chirish** huquqi berilganida ishlaydi. Bot shubhali belgilarni taxminiy aniqlaydi; APK’ni antivirus kabi tekshirmaydi.

Shaxsiy chatlarda avto o‘chirishni yoqish uchun botda **🗑 Avto o‘chirish sozlamasi → ✅ Yoqish** tugmasini bosing. Telegram Business → Chatbots sozlamasida **barcha xabarlarni o‘chirish** huquqini yoqing. Huquq berilmasa, bot xabarni o‘chira olmaydi va sizga ruxsat yetishmayotgani haqida xabar beradi. Bu sozlama guruh moderatsiyasiga ta’sir qilmaydi.

Yuborilgan xabar ostiga ogohlantirish yozish uchun **⚠️ Yuborilgan xabar ogohlantirishi → ✅ Yoqish**ni tanlang va Telegram Business’da **Javob berish** huquqini bering. Telegram ayrim chatlarda xabar yuborishni cheklashi mumkin.


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
