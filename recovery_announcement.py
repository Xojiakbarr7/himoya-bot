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
    await publish_channel(session, api_base, db)


async def publish_channel(session, api_base, db):
    campaign = "channel_recovery_public_2026_11_23"
    existing = await db([("SELECT 1 FROM qalqon_announcements WHERE campaign=%s", (campaign,))])
    if existing:
        return
    async with session.post(api_base+"/getChat", json={"chat_id":"@qalqon_ai1"}, allow_redirects=False) as response:
        result = await response.json()
    if not result.get("ok"):
        log.warning("Public recovery announcement: channel lookup failed")
        return
    chat = result["result"]
    if chat.get("type") != "channel" or chat.get("username", "").lower() != "qalqon_ai1":
        log.warning("Public recovery announcement: unexpected destination")
        return
    claimed = await db([("INSERT INTO qalqon_announcements VALUES(%s) ON CONFLICT DO NOTHING RETURNING campaign", (campaign,))])
    if not claimed:
        return
    body = TEXT.replace("Boshlash uchun pastdagi «Kanalni ulash» tugmasini bosing. Bot sizga bosqichma-bosqich yordam beradi.",
                        "Boshlash uchun pastdagi tugma orqali botga kiring. Menyudan «🔑 Kanalga qaytish» → «➕ Kanalni ulash»ni tanlang. Bot sizga bosqichma-bosqich yordam beradi.")
    payload = {"chat_id":chat["id"], "text":body, "reply_markup":{"inline_keyboard":[
        [{"text":"🛡 Qalqon AI botini ochish", "url":"https://t.me/Qalqonn_bot"}]]}}
    try:
        async with session.post(api_base+"/sendMessage",json=payload,allow_redirects=False) as response:
            sent = await response.json()
        if sent.get("ok"):
            log.info("Public recovery announcement sent: channel=%s message=%s", chat["id"],sent["result"]["message_id"])
        else:
            await db([("DELETE FROM qalqon_announcements WHERE campaign=%s",(campaign,))])
            log.warning("Public recovery announcement rejected: code=%s",sent.get("error_code"))
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        log.warning("Public recovery announcement delivery uncertain; not duplicated")
