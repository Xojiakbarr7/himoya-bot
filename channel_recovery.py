"""Owner-verified, persistent channel administrator recovery."""
import hashlib
import hmac
import json
import secrets
import time

BUTTON = "🔑 Kanalga qaytish"
RIGHTS = ("can_post_messages", "can_edit_messages", "can_delete_messages", "can_change_info",
          "can_invite_users", "can_promote_members", "can_manage_video_chats",
          "can_post_stories", "can_edit_stories", "can_delete_stories")
SCHEMA = [
    ("CREATE TABLE IF NOT EXISTS qalqon_recovery (chat BIGINT PRIMARY KEY, owner BIGINT NOT NULL, title TEXT NOT NULL, digest TEXT NOT NULL, rights TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE, failures INTEGER NOT NULL DEFAULT 0, locked_until DOUBLE PRECISION NOT NULL DEFAULT 0, invite TEXT, expires DOUBLE PRECISION NOT NULL DEFAULT 0)", ()),
    ("CREATE TABLE IF NOT EXISTS qalqon_recovery_log (chat BIGINT NOT NULL, owner BIGINT NOT NULL, action TEXT NOT NULL, created DOUBLE PRECISION NOT NULL)", ()),
]


async def handle(update, api, db):
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
            await tell(owner, "✅ Kanalga qaytish sozlandi.")
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
            await tell(owner, "✅ Administrator huquqlari qaytarildi.")
        else:
            expires = int(time.time()) + 600
            link = await api("createChatInviteLink", {"chat_id": chat, "expire_date": expires, "creates_join_request": True, "name": "Qalqon recovery"})
            db([("UPDATE qalqon_recovery SET invite=%s,expires=%s,failures=0,locked_until=0 WHERE chat=%s AND owner=%s", (link["invite_link"],expires,chat,owner))])
            log(chat, owner, "invite_created")
            await tell(owner, "Havola 10 daqiqa amal qiladi. Kanalga kirish so‘rovini yuboring.", [[{"text":"Kanalga qaytish","url":link["invite_link"]}]])
    except ValueError as exc:
        await tell(owner, str(exc) if not str(exc).startswith("invalid literal") else "Kanal ID raqam bo‘lishi kerak.")
    except KeyError:
        await tell(owner, "Telegram javobi yetarli emas. Qayta urining.")
    return True
