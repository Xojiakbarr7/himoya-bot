"""One-time, resumable announcement approved by the bot owner."""
import asyncio
import logging

import aiohttp

CAMPAIGN = "channel_recovery_2026_11_23"
TEXT = """🎉 Qalqon AI’da yangi imkoniyat — Kanalga qaytish!

🔑 Kanalingizni oldindan botga ulang va maxfiy tiklash kodini saqlang. Keyinchalik kanaldan chiqib ketsangiz, shu akkaunt orqali qaytib, tanlangan admin huquqlarini tiklashingiz mumkin.

Boshlash uchun pastdagi «Kanalni ulash» tugmasini bosing. Bot sizga bosqichma-bosqich yordam beradi.

⚠️ Kanal mavjud bo‘lishi va botda kerakli admin huquqlari saqlanishi kerak. Butunlay o‘chirilgan kanalni tiklash imkoni yo‘q. Kanal boshqa egaga topshirilsa, oldingi tiklash ruxsati bekor qilinadi.

✅ Funksiyadan foydalanish bepul."""
log = logging.getLogger("telegram_himoya")


async def run(session, api_base, execute):
    async def db(statements):
        return await asyncio.to_thread(execute, statements)

    await db([
        ("CREATE TABLE IF NOT EXISTS qalqon_announcements (campaign TEXT PRIMARY KEY)", ()),
        ("CREATE TABLE IF NOT EXISTS qalqon_announcement_delivery (campaign TEXT NOT NULL, owner BIGINT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', PRIMARY KEY(campaign,owner))", ()),
        ("""WITH created AS (
            INSERT INTO qalqon_announcements VALUES(%s) ON CONFLICT DO NOTHING RETURNING campaign
        ) INSERT INTO qalqon_announcement_delivery(campaign,owner)
          SELECT created.campaign,users.user_id FROM created CROSS JOIN qalqon_bot_users users
          WHERE users.user_id>0 ON CONFLICT DO NOTHING""", (CAMPAIGN,)),
    ])
    while True:
        rows = await db([("""UPDATE qalqon_announcement_delivery SET status='sending'
            WHERE campaign=%s AND owner=(SELECT owner FROM qalqon_announcement_delivery
            WHERE campaign=%s AND status='pending' ORDER BY owner LIMIT 1)
            AND status='pending' RETURNING owner""", (CAMPAIGN,CAMPAIGN))])
        if not rows:
            break
        owner = rows[0][0]
        payload = {"chat_id":owner,"text":TEXT,"reply_markup":{"inline_keyboard":[
            [{"text":"🔑 Kanalni ulash","callback_data":"recovery:add"}],
            [{"text":"📋 Kanallarim","callback_data":"recovery:list"}]]}}
        status = "unknown"
        for attempt in range(5):
            try:
                async with session.post(api_base+"/sendMessage",json=payload,allow_redirects=False) as response:
                    result = await response.json()
                if result.get("ok"):
                    status = "sent"
                    break
                if result.get("error_code") == 429:
                    await asyncio.sleep(min(60,max(1,result.get("parameters",{}).get("retry_after",5))))
                    continue
                status = "failed"
                break
            except (aiohttp.ClientError,asyncio.TimeoutError,ValueError):
                # Telegram has no sendMessage idempotency key. Do not duplicate an
                # ambiguously delivered announcement after a network timeout.
                break
        await db([("UPDATE qalqon_announcement_delivery SET status=%s WHERE campaign=%s AND owner=%s",(status,CAMPAIGN,owner))])
        await asyncio.sleep(.15)
    counts = await db([("SELECT status,COUNT(*) FROM qalqon_announcement_delivery WHERE campaign=%s GROUP BY status",(CAMPAIGN,))])
    log.info("Recovery announcement completed: %s",dict(counts))
