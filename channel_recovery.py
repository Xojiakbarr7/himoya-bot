"""Owner-verified, persistent channel administrator recovery."""
import hashlib
import hmac
import json
import secrets
import time
import logging
from urllib.parse import urlsplit

BUTTON = "🔑 Kanal / guruhga qaytish"
LEGACY_BUTTON = "🔑 Kanalga qaytish"
GROUP_RIGHTS = ("can_manage_chat", "can_delete_messages", "can_restrict_members",
                "can_change_info", "can_invite_users", "can_pin_messages",
                "can_promote_members", "can_manage_video_chats", "can_manage_topics")
RIGHTS = ("can_post_messages", "can_edit_messages", "can_delete_messages", "can_change_info",
          "can_invite_users", "can_promote_members", "can_manage_video_chats",
          "can_post_stories", "can_edit_stories", "can_delete_stories")
SCHEMA = [
    ("CREATE TABLE IF NOT EXISTS qalqon_recovery_dialog (owner BIGINT PRIMARY KEY, stage TEXT NOT NULL, chat BIGINT, expires DOUBLE PRECISION NOT NULL)", ()),
    ("CREATE TABLE IF NOT EXISTS qalqon_recovery (chat BIGINT PRIMARY KEY, owner BIGINT NOT NULL, title TEXT NOT NULL, digest TEXT NOT NULL, rights TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE, failures INTEGER NOT NULL DEFAULT 0, locked_until DOUBLE PRECISION NOT NULL DEFAULT 0, invite TEXT, expires DOUBLE PRECISION NOT NULL DEFAULT 0)", ()),
    ("CREATE TABLE IF NOT EXISTS qalqon_recovery_log (chat BIGINT NOT NULL, owner BIGINT NOT NULL, action TEXT NOT NULL, created DOUBLE PRECISION NOT NULL)", ()),
    ("CREATE TABLE IF NOT EXISTS qalqon_recovery_backup (chat BIGINT PRIMARY KEY, owner BIGINT NOT NULL, digest TEXT UNIQUE NOT NULL, claimant BIGINT, claim_until DOUBLE PRECISION NOT NULL DEFAULT 0, invite TEXT, used BOOLEAN NOT NULL DEFAULT FALSE)", ()),
    ("CREATE TABLE IF NOT EXISTS qalqon_recovery_backup_attempt (actor BIGINT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0, locked_until DOUBLE PRECISION NOT NULL DEFAULT 0)", ()),
]


async def handle_core(update, api, db):
    message = update.get("message") or {}
    query = update.get("callback_query") or {}
    event = update.get("chat_join_request") or update.get("my_chat_member")
    private = message.get("chat", {}).get("type") == "private"
    text = message.get("text", "") if private else ""
    data = query.get("data", "")
    relevant = text in {BUTTON, LEGACY_BUTTON} or text.startswith(("/kanal", "/tiklash")) or data.startswith("recover:")
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
            raise ValueError("Kanal yoki guruh egasi almashgan. Oldingi tiklash ruxsati bekor qilindi.")
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
                await tell(owner, "⚠️ Qaytish imkoniyati o‘chdi. Botning admin huquqlarini tekshiring.")
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
            await tell(owner, "✅ Qaytdingiz. Tanlangan admin huquqlari berildi.")
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
        if text in {BUTTON, LEGACY_BUTTON} or text == "/kanal":
            rows = db([("SELECT chat,title,enabled FROM qalqon_recovery WHERE owner=%s ORDER BY chat", (owner,))])
            lines = [f"{title} · {chat} · {'Faol' if enabled else 'Bekor qilingan'}" for chat,title,enabled in rows]
            await tell(owner, "🔑 Kanal yoki guruhga qaytish\n\nBotni kanal yoki guruhingizga admin qiling. Administrator qo‘shish va taklif qilish huquqlarini bering.\n\nUlash uchun yuboring\n/kanal @kanal_nomi\nYopiq kanal uchun raqamli kanal ID’sini kiriting.\n\nTiklash uchun\n/tiklash KANAL_ID MAXFIY_KOD\n\n" + "\n".join(lines))
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
            if info["type"] == "group":
                raise ValueError("Bu oddiy guruh. Telegram bot orqali admin tayinlash superguruhda ishlaydi. Guruhni superguruhga o‘tkazgach, uni qayta tanlang.")
            if info["type"] not in {"channel", "supergroup"}:
                raise ValueError("Kanal yoki superguruhni tanlang.")
            is_group = info["type"] == "supergroup"
            available_rights = GROUP_RIGHTS if is_group else RIGHTS
            basic_rights = ("can_delete_messages", "can_pin_messages") if is_group else RIGHTS[:2]
            basic_label = "Xabar o‘chirish va mahkamlash" if is_group else "Post joylash va tahrirlash"
            chat = info["id"]
            actual = await api("getChatMember", {"chat_id": chat, "user_id": owner})
            if actual["status"] != "creator":
                raise ValueError("Kanal yoki guruhni faqat uning hozirgi egasi ulashi mumkin.")
            member = await eligibility(chat, owner)
            if not data:
                await tell(owner, "Tiklanganda qaytariladigan huquqlarni tanlang.", [
                    [{"text": basic_label, "callback_data": f"recover:basic:{chat}"}],
                    [{"text": "Botdagi barcha admin huquqlari", "callback_data": f"recover:full:{chat}"}]])
                return True
            if mode not in {"basic", "full"}:
                return True
            rights = [k for k in (available_rights if mode == "full" else basic_rights) if member.get(k)]
            if not rights:
                raise ValueError("Botga tanlangan boshqaruv huquqlarini ham bering.")
            code = secrets.token_urlsafe(24)
            digest = hashlib.sha256(code.encode()).hexdigest()
            await tell(owner, f"🔐 Shu akkaunt uchun tiklash kodi\n{code}\n\nKanal/guruh ID\n{chat}\n\nBu kod faqat shu akkaunt uchun. Boshqa akkauntdan tiklash uchun alohida zaxira kalit yarating. Kanal yoki guruh butunlay o‘chirilsa tiklash ishlamaydi.")
            db([("INSERT INTO qalqon_recovery(chat,owner,title,digest,rights) VALUES(%s,%s,%s,%s,%s) ON CONFLICT(chat) DO UPDATE SET owner=excluded.owner,title=excluded.title,digest=excluded.digest,rights=excluded.rights,enabled=TRUE,failures=0,locked_until=0,invite=NULL,expires=0", (chat,owner,info["title"],digest,json.dumps(rights))), ("DELETE FROM qalqon_recovery_backup WHERE chat=%s", (chat,))])
            log(chat, owner, "registered")
            db([("DELETE FROM qalqon_recovery_dialog WHERE owner=%s", (owner,))])
            await tell(owner, "✅ Kanal yoki guruh ulandi. Boshqa akkauntdan qaytish uchun hozir zaxira kalit yarating.", [[{"text": "🔐 Zaxira kalit yaratish", "callback_data": f"backup:create:{chat}"}], [{"text": "Kanallarim va guruhlarim", "callback_data": "recovery:list"}]])
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
            await tell(owner, "Siz bu suhbat egasisiz. Adminlikni tiklash talab qilinmaydi.")
            return True
        if current["status"] == "kicked":
            raise ValueError("Bu suhbatda bloklangansiz. Hozirgi boshqaruvchi blokni olib tashlashi kerak.")
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
            await tell(owner, "Havola 10 daqiqa amal qiladi. Kirish so‘rovini yuboring.", [[{"text":"Qayta kirish","url":link["invite_link"]}]])
    except ValueError as exc:
        await tell(owner, str(exc) if not str(exc).startswith("invalid literal") else "Kanal/guruh ID raqam bo‘lishi kerak.")
    except KeyError:
        await tell(owner, "Telegram javobi yetarli emas. Qayta urining.")
    return True



async def handle_backup(update, api, db):
    """Separate opt-in bearer key; never changes the original owner's recovery code."""
    message = update.get("message") or {}
    query = update.get("callback_query") or {}
    event = update.get("chat_join_request")
    actor = (message.get("from") or query.get("from") or {}).get("id")
    private = message.get("chat", {}).get("type") == "private"
    data = query.get("data", "")
    if query and query.get("message", {}).get("chat", {}).get("id") != actor:
        return False
    if not db:
        if data.startswith("backup:"):
            await api("answerCallbackQuery", {"callback_query_id": query["id"]})
            await api("sendMessage", {"chat_id": actor, "text": "Baza vaqtincha ishlamayapti. Keyinroq qayta urining."})
            return True
        return False
    db(SCHEMA)
    dialog = db([("SELECT stage FROM qalqon_recovery_dialog WHERE owner=%s AND expires>%s", (actor,time.time()))]) if private and actor else []
    receiving = bool(dialog and dialog[0][0] == "backup_key" and not message.get("text", "").startswith("/"))
    if event:
        chat = event["chat"]["id"]
        link = event.get("invite_link", {}).get("invite_link")
        if not link:
            return False
        rows = db([("SELECT owner,claimant,claim_until,invite FROM qalqon_recovery_backup WHERE chat=%s AND used=FALSE AND invite=%s", (chat,link))])
        if not rows:
            return False
        original, target, until, _ = rows[0]
        applicant = event["from"]["id"]
        if applicant != target or until < time.time():
            await api("declineChatJoinRequest", {"chat_id":chat,"user_id":applicant})
            return True
    elif not data.startswith("backup:") and not receiving:
        return False

    async def send(user, body, rows=None):
        payload = {"chat_id":user,"text":body}
        if rows:
            payload["reply_markup"] = {"inline_keyboard":rows}
        await api("sendMessage", payload)

    async def check(chat, original):
        admins = await api("getChatAdministrators", {"chat_id":chat})
        creators = [a["user"]["id"] for a in admins if a["status"] == "creator"]
        # A deleted creator may be absent; a different visible creator must block recovery.
        if creators and creators != [original]:
            raise ValueError("Kanal yoki guruh egasini tasdiqlab bo‘lmadi yoki egasi o‘zgargan. Xavfsizlik uchun tiklash to‘xtatildi.")
        bot = await api("getMe", {})
        member = await api("getChatMember", {"chat_id":chat,"user_id":bot["id"]})
        if member.get("status") != "administrator" or not member.get("can_promote_members") or not member.get("can_invite_users"):
            raise ValueError("Botga administrator qo‘shish va taklif qilish huquqlarini bering.")
        return member

    try:
        if query:
            await api("answerCallbackQuery", {"callback_query_id":query["id"]})
        if data == "backup:enter":
            db([("INSERT INTO qalqon_recovery_dialog VALUES(%s,'backup_key',NULL,%s) ON CONFLICT(owner) DO UPDATE SET stage='backup_key',chat=NULL,expires=excluded.expires", (actor,time.time()+900))])
            await send(actor,"🔑 Oldindan yaratilgan zaxira kalitni yuboring. U QALQON_ bilan boshlanadi.\n\nAvvalgi qisqa tiklash kodi boshqa akkauntdan kirish uchun ishlamaydi. Zaxira kalitni kanal yoki guruh egasi oldindan yaratishi kerak.")
            return True
        if data.startswith(("backup:create:", "backup:revoke:")):
            chat = int(data.rsplit(":",1)[1])
            rows = db([("SELECT owner FROM qalqon_recovery WHERE chat=%s AND owner=%s AND enabled=TRUE",(chat,actor))])
            if not rows:
                raise ValueError("Avval kanal yoki guruhni egasi sifatida ulang.")
            actual = await api("getChatMember", {"chat_id":chat,"user_id":actor})
            if actual.get("status") != "creator":
                raise ValueError("Zaxira kalitni faqat kanal yoki guruhning hozirgi egasi yaratishi mumkin.")
            await check(chat,actor)
            if data.startswith("backup:revoke:"):
                db([("DELETE FROM qalqon_recovery_backup WHERE chat=%s AND owner=%s",(chat,actor))])
                await send(actor,"✅ Zaxira kalit bekor qilindi.")
                return True
            key = "QALQON_" + secrets.token_urlsafe(32)
            digest = hashlib.sha256(key.encode()).hexdigest()
            db([("INSERT INTO qalqon_recovery_backup(chat,owner,digest) VALUES(%s,%s,%s) ON CONFLICT(chat) DO UPDATE SET owner=excluded.owner,digest=excluded.digest,claimant=NULL,claim_until=0,invite=NULL,used=FALSE",(chat,actor,digest))])
            await send(actor,"🔐 Boshqa akkaunt uchun zaxira kalit:\n"+key+"\n\nQALQON_ bilan boshlangan kalitni to‘liq nusxalab, Telegramdan tashqarida xavfsiz saqlang. Bu kalitni bilgan odam boshqa akkauntdan admin bo‘lishi mumkin. Yangi kalit yaratsangiz, eskisi bekor bo‘ladi. Kanalni boshqa kishiga topshirishdan avval kalitni bekor qiling.")
            return True
        if receiving:
            key = (message.get("text") or "").strip()
            if key == "❌ Bekor qilish":
                db([("DELETE FROM qalqon_recovery_dialog WHERE owner=%s",(actor,))])
                await send(actor,"Bekor qilindi.")
                return True
            if key.startswith("QALQON_") and message.get("message_id"):
                try:
                    await api("deleteMessage", {"chat_id":actor,"message_id":message["message_id"]})
                except RuntimeError:
                    # Deletion is best-effort: never print the key or block recovery.
                    pass
            if not key.startswith("QALQON_"):
                await send(actor,"⚠️ Bu zaxira kalitga o‘xshamaydi. Boshqa akkauntdan kirish uchun QALQON_ bilan boshlanadigan kalit kerak.\n\nUni kanal egasi eski akkauntda: Kanal / guruhga qaytish → Kanallarim va guruhlarim → kanalni tanlash → Zaxira kalit yaratish orqali oladi. Avvalgi qisqa kod faqat o‘sha akkaunt uchun.")
                return True
            now = time.time()
            db([("INSERT INTO qalqon_recovery_backup_attempt(actor) VALUES(%s) ON CONFLICT(actor) DO NOTHING",(actor,))])
            attempts = db([("SELECT locked_until FROM qalqon_recovery_backup_attempt WHERE actor=%s",(actor,))])
            if attempts and attempts[0][0] > now:
                raise ValueError("Juda ko‘p urinish. 15 daqiqadan keyin qayta urinib ko‘ring.")
            digest = hashlib.sha256(key.encode()).hexdigest()
            rows = db([("SELECT b.chat,b.owner,r.rights FROM qalqon_recovery_backup b JOIN qalqon_recovery r ON r.chat=b.chat AND r.owner=b.owner WHERE b.digest=%s AND b.used=FALSE AND r.enabled=TRUE",(digest,))])
            if not rows:
                db([("UPDATE qalqon_recovery_backup_attempt SET failures=failures+1,locked_until=CASE WHEN failures>=4 THEN %s ELSE locked_until END WHERE actor=%s",(now+900,actor))])
                raise ValueError("Kalit noto‘g‘ri yoki ishlatilgan.")
            chat,original,rights = rows[0]
            member = await check(chat,original)
            claimed = db([("UPDATE qalqon_recovery_backup SET claimant=%s,claim_until=%s WHERE chat=%s AND digest=%s AND used=FALSE AND (claimant IS NULL OR claimant=%s OR claim_until<%s) RETURNING chat",(actor,now+600,chat,digest,actor,now))])
            if not claimed:
                raise ValueError("Kalit bilan boshqa tiklash jarayoni boshlangan. Keyinroq urining.")
            current = await api("getChatMember", {"chat_id":chat,"user_id":actor})
            if current.get("status") == "kicked":
                raise ValueError("Akkaunt bloklangan. Amaldagi administrator blokni olib tashlashi kerak.")
            if current.get("status") in {"member","administrator","creator"}:
                if current.get("status") == "member":
                    granted = {k:True for k in json.loads(rights) if member.get(k)}
                    if not granted:
                        raise ValueError("Botda tanlangan admin huquqlari qolmagan.")
                    await api("promoteChatMember", {"chat_id":chat,"user_id":actor,**granted})
                db([("UPDATE qalqon_recovery_backup SET used=TRUE,invite=NULL WHERE chat=%s AND claimant=%s",(chat,actor)),("DELETE FROM qalqon_recovery_dialog WHERE owner=%s",(actor,))])
                await send(actor,"✅ Kanal yoki guruhga administrator sifatida kirishingiz tayyor. Kalit ishlatildi.")
                return True
            link = await api("createChatInviteLink", {"chat_id":chat,"expire_date":int(now)+600,"creates_join_request":True,"name":"Qalqon backup"})
            saved = db([("UPDATE qalqon_recovery_backup SET invite=%s WHERE chat=%s AND digest=%s AND claimant=%s AND used=FALSE RETURNING chat",(link["invite_link"],chat,digest,actor))])
            if not saved:
                raise ValueError("Kalit bekor qilingan. Qayta sozlash kerak.")
            db([("DELETE FROM qalqon_recovery_dialog WHERE owner=%s",(actor,)),("UPDATE qalqon_recovery_backup_attempt SET failures=0,locked_until=0 WHERE actor=%s",(actor,))])
            await send(actor,"Havolani bosing va kirish so‘rovini yuboring. Havola 10 daqiqa amal qiladi.",[[{"text":"Kanal / guruhga kirish","url":link["invite_link"]}]])
            return True
        if event:
            rows = db([("SELECT rights FROM qalqon_recovery WHERE chat=%s AND owner=%s AND enabled=TRUE",(chat,original))])
            if not rows:
                raise ValueError("Tiklash ruxsati bekor qilingan.")
            member = await check(chat,original)
            granted = {k:True for k in json.loads(rows[0][0]) if member.get(k)}
            if not granted:
                raise ValueError("Botda tanlangan admin huquqlari qolmagan.")
            await api("approveChatJoinRequest", {"chat_id":chat,"user_id":target})
            await api("promoteChatMember", {"chat_id":chat,"user_id":target,**granted})
            db([("UPDATE qalqon_recovery_backup SET used=TRUE,invite=NULL WHERE chat=%s AND claimant=%s",(chat,target))])
            await send(target,"✅ Qaytdingiz. Tanlangan administrator huquqlari berildi. Zaxira kalit ishlatildi.")
            try:
                await api("revokeChatInviteLink", {"chat_id":chat,"invite_link":link})
            except RuntimeError:
                pass
            return True
    except (ValueError, RuntimeError) as exc:
        recipient = target if event else actor
        if recipient:
            await send(recipient, str(exc) if isinstance(exc, ValueError) else "Telegram amalni bajarmadi. Bot huquqlarini tekshirib, kalitni qayta yuboring.")
        return True
    return True


async def handle(update, api, db):
    if await handle_backup(update, api, db):
        return True
    message = update.get("message") or {}
    query = update.get("callback_query") or {}
    private = message.get("chat", {}).get("type") == "private"
    text = message.get("text", "").strip() if private else ""
    data = query.get("data", "")
    owner = (message.get("from") or query.get("from") or {}).get("id")
    if query and query.get("message", {}).get("chat", {}).get("id") != owner:
        return False
    relevant = text in {BUTTON, LEGACY_BUTTON, "/kanal", "/tiklash"} or data.startswith("recovery:")
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
                await api("sendMessage", {"chat_id": owner, "text": "Telegram amalni bajarmadi. Bot kanal yoki guruhda admin ekanini va admin qo‘shish huquqini tekshiring. Kanal yoki guruhni qayta tanlab urining."})
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
        if text in {BUTTON, LEGACY_BUTTON} or text in {"/kanal", "/tiklash"} or data == "recovery:home" or text == "❌ Bekor qilish":
            db([("DELETE FROM qalqon_recovery_dialog WHERE owner=%s", (owner,))])
            await send("🔑 Kanal yoki guruhga qaytish\n\nAvval kanal yoki guruhingizni ulang. Boshqa akkauntdan qaytish uchun oldindan zaxira kalit yarating va uni xavfsiz saqlang.", [
                [{"text":"➕ Kanal / guruhni ulash","callback_data":"recovery:add"}],
                [{"text":"📋 Kanallarim va guruhlarim","callback_data":"recovery:list"}],
                [{"text":"🔐 Zaxira kalit bilan kirish","callback_data":"backup:enter"}]])
            return True
        if data == "recovery:add":
            stage("channel")
            await send("1. Qalqon botni kanal yoki guruhingizga admin qiling.\n2. «Administrator qo‘shish» va «Taklif qilish» huquqlarini yoqing.\n3. Pastdagi tugmadan kanal yoki guruhingizni tanlang.\n\nYoki kanal havolasini yuboring, yoxud kanaldagi postni shu yerga forward qiling.", keyboard={
                "keyboard":[
                    [{"text":"📢 Kanalni tanlash","request_chat":{"request_id":7351,"chat_is_channel":True,"chat_is_created":True,"request_title":True}}],
                    [{"text":"👥 Guruhni tanlash","request_chat":{"request_id":7352,"chat_is_channel":False,"chat_is_created":True,"request_title":True}}],
                    ["❌ Bekor qilish"]],
                "resize_keyboard":True,"one_time_keyboard":True})
            return True
        if data == "recovery:list":
            rows = db([("SELECT chat,title,enabled FROM qalqon_recovery WHERE owner=%s ORDER BY chat LIMIT 40",(owner,))])
            await send("Qaytmoqchi bo‘lgan kanal yoki guruhingizni tanlang." if rows else "Hali kanal yoki guruh ulanmagan. Ulash tugmasini bosing.",
                       [[{"text": title[:40] + (" · bekor qilingan" if not enabled else ""), "callback_data":f"recovery:pick:{chat}"}] for chat,title,enabled in rows] + back)
            return True
        if data.startswith("recovery:pick:"):
            chat = int(data.rsplit(":",1)[1])
            rows = db([("SELECT title FROM qalqon_recovery WHERE chat=%s AND owner=%s AND enabled=TRUE",(chat,owner))])
            if not rows:
                await send("Faol tiklash ruxsati topilmadi.", back)
                return True
            stage("code",chat)
            await send(f"{rows[0][0]}\n\nShu akkauntdan qaytish uchun avvalgi tiklash kodini yuboring. Boshqa akkaunt uchun esa oldindan zaxira kalit yarating.", [[{"text":"🔐 Zaxira kalit yaratish","callback_data":f"backup:create:{chat}"}], [{"text":"🗑 Zaxira kalitni bekor qilish","callback_data":f"backup:revoke:{chat}"}]] + back)
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
                channel = shared.get("chat_id") if shared.get("request_id") in {7351,7352} else None
                channel = channel or (forwarded or {}).get("id")
                if not channel:
                    channel = text
                    if text.startswith(("https://t.me/","http://t.me/","t.me/")):
                        path = urlsplit(text if "://" in text else "https://"+text).path.strip("/").split("/")[0]
                        channel = "@"+path
                    if not (str(channel).startswith("@") or str(channel).lstrip("-").isdigit()):
                        await send("Kanal yoki guruhni pastdagi tanlash tugmasidan tanlang. Masalan, @kanal_nomi ham yuborishingiz mumkin.",back)
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
        await send("Telegram yoki baza so‘rovni bajarmadi. Bot kanal yoki guruhda admin ekanini va kerakli huquqlarini tekshiring, keyin qayta urining.",back)
    return True

