"""Owner-verified, persistent channel administrator recovery."""
import hashlib
import hmac
import json
import secrets
import time
import logging
from urllib.parse import urlsplit

BUTTON = "🔑 Kanalga qaytish"
RIGHTS = ("can_post_messages", "can_edit_messages", "can_delete_messages", "can_change_info",
          "can_invite_users", "can_promote_members", "can_manage_video_chats",
          "can_post_stories", "can_edit_stories", "can_delete_stories")
SCHEMA = [
    ("CREATE TABLE IF NOT EXISTS qalqon_recovery_dialog (owner BIGINT PRIMARY KEY, stage TEXT NOT NULL, chat BIGINT, expires DOUBLE PRECISION NOT NULL)", ()),
    ("CREATE TABLE IF NOT EXISTS qalqon_recovery (chat BIGINT PRIMARY KEY, owner BIGINT NOT NULL, title TEXT NOT NULL, digest TEXT NOT NULL, rights TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE, failures INTEGER NOT NULL DEFAULT 0, locked_until DOUBLE PRECISION NOT NULL DEFAULT 0, invite TEXT, expires DOUBLE PRECISION NOT NULL DEFAULT 0)", ()),
    ("CREATE TABLE IF NOT EXISTS qalqon_recovery_log (chat BIGINT NOT NULL, owner BIGINT NOT NULL, action TEXT NOT NULL, created DOUBLE PRECISION NOT NULL)", ()),
]


async def handle_core(update, api, db):
    message = update.get("message") or {}
    query = update.get("callback_query") or {}
    event = update.get("chat_join_request") or update.get("my_chat_member")
    private = message.get("chat", {}).get("type") == "private"
    text = message.get("text", "") if private else ""
    data = query.get("data", "")
    relevant = text == BUTTON or text.startswith(("/kanal", "/tiklash")) or data.startswith("recover:")
    if not relevant and not event:
        return False

    async def tell(owner, text, keyboard=None):
        payload = {"chat_id": owner, "text": text}
        if keyboard:
            payload["reply_markup"] = {"inline_keyboard": keyboard}
        await api("sendMessage", payload)

    if db is None:
        if relevant:
            owner = message.get("from", query.get("from", {}))["id"]
            await tell(owner, "Kanalni tiklash bazasi vaqtincha mavjud emas. Keyinroq urining.")
        return True
    db(SCHEMA)

    def log(chat, owner, action):
        db([("INSERT INTO qalqon_recovery_log VALUES(%s,%s,%s,%s)", (chat, owner, action, time.time()))])

    async def eligibility(chat, owner):
        admins = await api("getChatAdministrators", {"chat_id": chat})
        creators = [a["user"]["id"] for a in admins if a["status"] == "creator"]
        if creators and creators != [owner]:
            db([("UPDATE qalqon_recovery SET enabled=FALSE, invite=NULL, expires=0 WHERE chat=%s", (chat,))])
            log(chat, owner, "ownership_changed")
            raise ValueError("Kanal egasi almashgan. Oldingi tiklash ruxsati bekor qilindi.")
        bot = await api("getMe", {})
        member = await api("getChatMember", {"chat_id": chat, "user_id": bot["id"]})
        if member["status"] != "administrator" or not member.get("can_promote_members") or not member.get("can_invite_users"):
            raise ValueError("Botga administrator qo‘shish va foydalanuvchi taklif qilish huquqlarini bering.")
        return member

    if event:
        chat = event["chat"]["id"]
        rows = db([("SELECT owner,rights,invite,expires FROM qalqon_recovery WHERE chat=%s AND enabled=TRUE", (chat,))])
        if not rows:
            return True
        owner, rights, invite, expires = rows[0]
        if "my_chat_member" in update:
            new = event["new_chat_member"]
            if new["status"] != "administrator" or not new.get("can_promote_members") or not new.get("can_invite_users"):
                db([("UPDATE qalqon_recovery SET invite=NULL,expires=0 WHERE chat=%s", (chat,))])
                log(chat, owner, "bot_rights_lost")
                await tell(owner, "⚠️ Kanalga qaytish imkoniyati o‘chdi. Botning admin huquqlarini tekshiring.")
            return True
        if event.get("invite_link", {}).get("invite_link") != invite or not invite:
            return True
        applicant = event["from"]["id"]
        if applicant != owner or expires < time.time():
            await api("declineChatJoinRequest", {"chat_id": chat, "user_id": applicant})
            return True
        try:
            member = await eligibility(chat, owner)
            await api("approveChatJoinRequest", {"chat_id": chat, "user_id": owner})
            granted = {key: True for key in json.loads(rights) if member.get(key)}
            await api("promoteChatMember", {"chat_id": chat, "user_id": owner, **granted})
            db([("UPDATE qalqon_recovery SET invite=NULL,expires=0 WHERE chat=%s", (chat,))])
            log(chat, owner, "administrator_restored")
            db([("DELETE FROM qalqon_recovery_dialog WHERE owner=%s", (owner,))])
            await tell(owner, "✅ Kanalga qaytdingiz. Tanlangan admin huquqlari berildi.")
            await api("revokeChatInviteLink", {"chat_id": chat, "invite_link": invite})
        except ValueError as exc:
            await tell(owner, str(exc))
        return True

    owner = (message.get("from") or query.get("from"))["id"]
    if query:
        if query.get("message", {}).get("chat", {}).get("id") != owner:
            return True
        await api("answerCallbackQuery", {"callback_query_id": query["id"]})
    try:
        if text == BUTTON or text == "/kanal":
            rows = db([("SELECT chat,title,enabled FROM qalqon_recovery WHERE owner=%s ORDER BY chat", (owner,))])
            lines = [f"{title} · {chat} · {'Faol' if enabled else 'Bekor qilingan'}" for chat,title,enabled in rows]
            await tell(owner, "🔑 Kanalga qaytish\n\nBotni kanalingizga admin qiling. Administrator qo‘shish va taklif qilish huquqlarini bering.\n\nUlash uchun yuboring\n/kanal @kanal_nomi\nYopiq kanal uchun raqamli kanal ID’sini kiriting.\n\nTiklash uchun\n/tiklash KANAL_ID MAXFIY_KOD\n\n" + "\n".join(lines))
            return True
        if text.startswith("/kanal ") or data.startswith("recover:"):
            mode = "basic"
            if data:
                _, mode, chat = data.split(":")
                chat = int(chat)
            else:
                chat = text.split(maxsplit=1)[1].strip()
                chat = int(chat) if chat.lstrip("-").isdigit() else chat
            info = await api("getChat", {"chat_id": chat})
            if info["type"] != "channel":
                raise ValueError("Faqat kanallarni ulash mumkin.")
            chat = info["id"]
            actual = await api("getChatMember", {"chat_id": chat, "user_id": owner})
            if actual["status"] != "creator":
                raise ValueError("Kanalni faqat uning hozirgi egasi ulashi mumkin.")
            member = await eligibility(chat, owner)
            if not data:
                await tell(owner, "Tiklanganda qaytariladigan huquqlarni tanlang.", [
                    [{"text": "Post joylash va tahrirlash", "callback_data": f"recover:basic:{chat}"}],
                    [{"text": "Botdagi barcha admin huquqlari", "callback_data": f"recover:full:{chat}"}]])
                return True
            if mode not in {"basic", "full"}:
                return True
            rights = [k for k in (RIGHTS if mode == "full" else RIGHTS[:2]) if member.get(k)]
            if not rights:
                raise ValueError("Botga post joylash huquqini ham bering.")
            code = secrets.token_urlsafe(24)
            digest = hashlib.sha256(code.encode()).hexdigest()
            await tell(owner, f"🔐 Tiklash kodingiz\n{code}\n\nKanal ID\n{chat}\n\nKodni ishonchli joyga saqlang. Tiklash shu Telegram akkauntiga bog‘langan. Kanal butunlay o‘chirilsa tiklash ishlamaydi.")
            db([("INSERT INTO qalqon_recovery(chat,owner,title,digest,rights) VALUES(%s,%s,%s,%s,%s) ON CONFLICT(chat) DO UPDATE SET owner=excluded.owner,title=excluded.title,digest=excluded.digest,rights=excluded.rights,enabled=TRUE,failures=0,locked_until=0,invite=NULL,expires=0", (chat,owner,info["title"],digest,json.dumps(rights)))])
            log(chat, owner, "registered")
            db([("DELETE FROM qalqon_recovery_dialog WHERE owner=%s", (owner,))])
            await tell(owner, "✅ Kanalga qaytish sozlandi. Qaytish kerak bo‘lsa, «Kanallarim»dan kanalni tanlab kodingizni yuboring.", [[{"text": "Kanallarim", "callback_data": "recovery:list"}]])
            return True
        parts = text.split()
        if len(parts) != 3:
            raise ValueError("Quyidagicha yuboring\n/tiklash KANAL_ID MAXFIY_KOD")
        chat = int(parts[1])
        rows = db([("SELECT digest,rights,locked_until FROM qalqon_recovery WHERE chat=%s AND owner=%s AND enabled=TRUE", (chat, owner))])
        if not rows:
            raise ValueError("Bu akkaunt uchun faol tiklash ruxsati topilmadi.")
        digest, rights, locked = rows[0]
        if locked > time.time():
            raise ValueError("Urinishlar ko‘paydi. 15 daqiqadan so‘ng qayta urining.")
        if not hmac.compare_digest(digest, hashlib.sha256(parts[2].encode()).hexdigest()):
            db([("UPDATE qalqon_recovery SET failures=failures+1,locked_until=CASE WHEN failures>=4 THEN %s ELSE locked_until END WHERE chat=%s", (time.time()+900,chat))])
            log(chat, owner, "code_rejected")
            raise ValueError("Tiklash kodi noto‘g‘ri.")
        member = await eligibility(chat, owner)
        current = await api("getChatMember", {"chat_id": chat, "user_id": owner})
        if current["status"] == "creator":
            await tell(owner, "Siz kanal egasisiz. Adminlikni tiklash talab qilinmaydi.")
            return True
        if current["status"] == "kicked":
            raise ValueError("Kanalda bloklangansiz. Hozirgi kanal boshqaruvchisi blokni olib tashlashi kerak.")
        if current["status"] in {"member", "administrator"}:
            granted = {key: True for key in json.loads(rights) if member.get(key)}
            await api("promoteChatMember", {"chat_id": chat, "user_id": owner, **granted})
            log(chat, owner, "administrator_restored")
            db([("DELETE FROM qalqon_recovery_dialog WHERE owner=%s", (owner,))])
            await tell(owner, "✅ Administrator huquqlari qaytarildi.")
        else:
            expires = int(time.time()) + 600
            link = await api("createChatInviteLink", {"chat_id": chat, "expire_date": expires, "creates_join_request": True, "name": "Qalqon recovery"})
            db([("UPDATE qalqon_recovery SET invite=%s,expires=%s,failures=0,locked_until=0 WHERE chat=%s AND owner=%s", (link["invite_link"],expires,chat,owner))])
            log(chat, owner, "invite_created")
            db([("DELETE FROM qalqon_recovery_dialog WHERE owner=%s", (owner,))])
            await tell(owner, "Havola 10 daqiqa amal qiladi. Kanalga kirish so‘rovini yuboring.", [[{"text":"Kanalga qaytish","url":link["invite_link"]}]])
    except ValueError as exc:
        await tell(owner, str(exc) if not str(exc).startswith("invalid literal") else "Kanal ID raqam bo‘lishi kerak.")
    except KeyError:
        await tell(owner, "Telegram javobi yetarli emas. Qayta urining.")
    return True



async def handle(update, api, db):
    message = update.get("message") or {}
    query = update.get("callback_query") or {}
    private = message.get("chat", {}).get("type") == "private"
    text = message.get("text", "").strip() if private else ""
    data = query.get("data", "")
    owner = (message.get("from") or query.get("from") or {}).get("id")
    if query and query.get("message", {}).get("chat", {}).get("id") != owner:
        return False
    relevant = text in {BUTTON, "/kanal", "/tiklash"} or data.startswith("recovery:")
    dialog = []
    if db and private and owner:
        db(SCHEMA)
        dialog = db([("SELECT stage,chat FROM qalqon_recovery_dialog WHERE owner=%s AND expires>%s", (owner, time.time()))])
    relevant = relevant or bool(dialog)
    if not relevant:
        try:
            return await handle_core(update, api, db)
        except RuntimeError:
            if owner and (text.startswith(("/kanal", "/tiklash")) or data.startswith("recover:")):
                await api("sendMessage", {"chat_id": owner, "text": "Telegram amalni bajarmadi. Bot kanalda admin ekanini va admin qo‘shish huquqini tekshiring. Kanalni qayta tanlab urining."})
                return True
            raise

    async def send(body, rows=None, keyboard=None):
        payload = {"chat_id": owner, "text": body}
        if rows:
            payload["reply_markup"] = {"inline_keyboard": rows}
        if keyboard:
            payload["reply_markup"] = keyboard
        await api("sendMessage", payload)

    def stage(name, chat=None):
        db([("INSERT INTO qalqon_recovery_dialog VALUES(%s,%s,%s,%s) ON CONFLICT(owner) DO UPDATE SET stage=excluded.stage,chat=excluded.chat,expires=excluded.expires", (owner,name,chat,time.time()+900))])

    back = [[{"text": "⬅️ Ortga", "callback_data": "recovery:home"}]]
    try:
        if query:
            await api("answerCallbackQuery", {"callback_query_id": query["id"]})
        if not db:
            await send("Baza bilan ulanish vaqtincha uzilgan. Keyinroq qayta urining.")
            return True
        db(SCHEMA)
        if text == BUTTON or text in {"/kanal", "/tiklash"} or data == "recovery:home" or text == "❌ Bekor qilish":
            db([("DELETE FROM qalqon_recovery_dialog WHERE owner=%s", (owner,))])
            await send("🔑 Kanalga qaytish\n\nAvval kanalingizni ulang va berilgan maxfiy kodni saqlang. Keyinchalik shu akkaunt orqali kanalga qaytishingiz mumkin.", [
                [{"text":"➕ Kanalni ulash","callback_data":"recovery:add"}],
                [{"text":"📋 Kanallarim","callback_data":"recovery:list"}]])
            return True
        if data == "recovery:add":
            stage("channel")
            await send("1. Qalqon botni kanalingizga admin qiling.\n2. «Administrator qo‘shish» va «Taklif qilish» huquqlarini yoqing.\n3. Pastdagi tugmadan kanalingizni tanlang.\n\nYoki kanal havolasini yuboring, yoxud kanaldagi postni shu yerga forward qiling.", keyboard={
                "keyboard":[[{"text":"📢 Kanalni tanlash","request_chat":{"request_id":7351,"chat_is_channel":True,"chat_is_created":True,"request_title":True}}],["❌ Bekor qilish"]],
                "resize_keyboard":True,"one_time_keyboard":True})
            return True
        if data == "recovery:list":
            rows = db([("SELECT chat,title,enabled FROM qalqon_recovery WHERE owner=%s ORDER BY chat LIMIT 40",(owner,))])
            await send("Qaytmoqchi bo‘lgan kanalingizni tanlang." if rows else "Hali kanal ulanmagan. «Kanalni ulash» tugmasini bosing.",
                       [[{"text": title[:40] + (" · bekor qilingan" if not enabled else ""), "callback_data":f"recovery:pick:{chat}"}] for chat,title,enabled in rows] + back)
            return True
        if data.startswith("recovery:pick:"):
            chat = int(data.rsplit(":",1)[1])
            rows = db([("SELECT title FROM qalqon_recovery WHERE chat=%s AND owner=%s AND enabled=TRUE",(chat,owner))])
            if not rows:
                await send("Faol tiklash ruxsati topilmadi.", back)
                return True
            stage("code",chat)
            await send(f"{rows[0][0]}\n\nUlash paytida berilgan maxfiy tiklash kodini yuboring. Kod 15 daqiqa ichida kiritilishi kerak.",back)
            return True
        if dialog:
            step, chat = dialog[0]
            if text.startswith("/") or text in {"☰ Menyuni ochish","✖️ Menyuni yopish"}:
                db([("DELETE FROM qalqon_recovery_dialog WHERE owner=%s",(owner,))])
                return False
            if step == "channel":
                shared = message.get("chat_shared") or {}
                origin = message.get("forward_origin") or {}
                forwarded = origin.get("chat") if origin.get("type") == "channel" else message.get("forward_from_chat")
                channel = shared.get("chat_id") if shared.get("request_id") == 7351 else None
                channel = channel or (forwarded or {}).get("id")
                if not channel:
                    channel = text
                    if text.startswith(("https://t.me/","http://t.me/","t.me/")):
                        path = urlsplit(text if "://" in text else "https://"+text).path.strip("/").split("/")[0]
                        channel = "@"+path
                    if not (str(channel).startswith("@") or str(channel).lstrip("-").isdigit()):
                        await send("Kanalni tugma orqali tanlang yoki kanaldagi postni forward qiling. Masalan, @kanal_nomi ham yuborishingiz mumkin.",back)
                        return True
                translated = dict(message,text=f"/kanal {channel}")
            else:
                translated = dict(message,text=f"/tiklash {chat} {text}")
            await handle_core({"message":translated},api,db)
            return True
        return True
    except ValueError:
        await send("Kanal ma’lumoti noto‘g‘ri. Qayta tanlang.",back)
    except RuntimeError:
        logging.getLogger("telegram_himoya").warning("Channel recovery operation failed")
        await send("Telegram yoki baza so‘rovni bajarmadi. Bot kanalda admin ekanini va kerakli huquqlarini tekshiring, keyin qayta urining.",back)
    return True
