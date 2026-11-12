"""Telegram Business security assistant.

This starter monitors only business chats explicitly granted to the bot. It
does not download files or send message contents to third-party services.
"""

from __future__ import annotations

import asyncio
import html
import ipaddress
import logging
import os
import re
import sqlite3
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web


def load_dotenv(path: Path = Path(".env")) -> None:
    """Load simple KEY=VALUE entries without requiring a dotenv dependency."""
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if value.startswith(("'", '"')) and value.endswith(value[:1]):
            value = value[1:-1]
        if key:
            os.environ.setdefault(key, value)


load_dotenv()
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))
DB_PATH = Path(os.environ.get("DATABASE_PATH", str(DATA_DIR / "himoya.sqlite3")))
API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}"
POLL_TIMEOUT = 30
MAX_ALERT_TEXT = 3500
WEBHOOK_PATH = "/telegram/webhook"
BUTTON_STATUS = "📊 Bot holati"
BUTTON_TIPS = "🔐 Xavfsizlik maslahatlari"
BUTTON_SCAN = "🔎 Xabarni tekshirish"
BUTTON_HELP = "ℹ️ Qanday ishlaydi"
BUTTON_DELETE_MODE = "🗑 Avto o‘chirish sozlamasi"
MAIN_KEYBOARD = {
    "keyboard": [
        [BUTTON_STATUS, BUTTON_TIPS],
        [BUTTON_SCAN, BUTTON_HELP],
        [BUTTON_DELETE_MODE],
    ],
    "resize_keyboard": True,
    "is_persistent": True,
    "input_field_placeholder": "Tugmalardan birini tanlang",
}
ALLOWED_UPDATES = [
    "message", "business_connection", "business_message",
    "edited_business_message", "edited_message", "callback_query",
]

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("telegram_himoya")

URL_RE = re.compile(r"(?i)(?:https?://|www\.)[^\s<>\]\[(){}\"']+|\bt\.me/[^\s<>\]\[(){}\"']+")
TRAILING_URL_PUNCTUATION = ".,!?;:)]}>'\""
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy",
    "tiny.cc", "shorturl.at", "soo.gd", "rebrand.ly", "ow.ly",
}
SUSPICIOUS_PHRASES = (
    "sms kod", "telegram kodi", "tasdiqlash kodi", "kodni yubor",
    "kodni ayt", "akkauntingiz blok", "akkaunt blok", "tezda to'lov",
    "pul o'tkazing", "sovrin yutdingiz", "hisobingizni tasdiqlang",
    "пароль", "код подтверждения", "отправьте код", "аккаунт заблок",
    "переведите деньги", "вы выиграли", "подтвердите аккаунт",
)
GROUP_SCAM_PHRASES = (
    "sms kod", "telegram kodi", "tasdiqlash kodi", "kodni yubor",
    "kodni ayt", "akkauntingiz blok", "akkaunt blok", "tezda to'lov",
    "pul o'tkazing", "sovrin yutdingiz", "hisobingizni tasdiqlang",
    "отправьте код", "аккаунт заблок", "переведите деньги",
    "вы выиграли", "подтвердите аккаунт",
)
EXECUTABLE_SUFFIXES = (".exe", ".scr", ".msi", ".jar", ".bat", ".cmd")


class TelegramAPIError(RuntimeError):
    pass


class Store:
    """Persist only connection routing and update offset, never message text."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS connections ("
            "connection_id TEXT PRIMARY KEY, owner_chat_id INTEGER NOT NULL, "
            "owner_user_id INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS user_settings ("
            "owner_user_id INTEGER PRIMARY KEY, auto_delete_harmful INTEGER NOT NULL DEFAULT 0)"
        )
        self.db.commit()

    def save_connection(self, connection: dict[str, Any]) -> None:
        connection_id = connection.get("id")
        user = connection.get("user") or {}
        owner_chat_id = connection.get("user_chat_id")
        owner_user_id = user.get("id")
        if not connection_id or not owner_chat_id or not owner_user_id:
            log.warning("Business ulanishida egani aniqlash uchun ma'lumot yetarli emas")
            return
        enabled = int(bool(connection.get("is_enabled", True)))
        self.db.execute(
            "INSERT INTO connections(connection_id, owner_chat_id, owner_user_id, enabled) "
            "VALUES(?,?,?,?) ON CONFLICT(connection_id) DO UPDATE SET "
            "owner_chat_id=excluded.owner_chat_id, owner_user_id=excluded.owner_user_id, "
            "enabled=excluded.enabled",
            (str(connection_id), int(owner_chat_id), int(owner_user_id), enabled),
        )
        self.db.commit()

    def connection(self, connection_id: str) -> tuple[int, int] | None:
        row = self.db.execute(
            "SELECT owner_chat_id, owner_user_id FROM connections "
            "WHERE connection_id=? AND enabled=1", (connection_id,)
        ).fetchone()
        return (int(row[0]), int(row[1])) if row else None

    def auto_delete_enabled(self, owner_user_id: int) -> bool:
        row = self.db.execute(
            "SELECT auto_delete_harmful FROM user_settings WHERE owner_user_id=?",
            (int(owner_user_id),),
        ).fetchone()
        return bool(row[0]) if row else False

    def set_auto_delete(self, owner_user_id: int, enabled: bool) -> None:
        self.db.execute(
            "INSERT INTO user_settings(owner_user_id, auto_delete_harmful) VALUES(?,?) "
            "ON CONFLICT(owner_user_id) DO UPDATE SET auto_delete_harmful=excluded.auto_delete_harmful",
            (int(owner_user_id), int(enabled)),
        )
        self.db.commit()

    def set_offset(self, offset: int) -> None:
        self.db.execute(
            "INSERT INTO state(key,value) VALUES('update_offset',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(offset),)
        )
        self.db.commit()

    def offset(self) -> int | None:
        row = self.db.execute("SELECT value FROM state WHERE key='update_offset'").fetchone()
        return int(row[0]) if row else None


def api_error_text(data: dict[str, Any]) -> str:
    return f"Telegram API xatosi ({data.get('error_code', '?')}): {data.get('description', 'noma’lum xato')}"


async def api(session: aiohttp.ClientSession, method: str, payload: dict[str, Any] | None = None) -> Any:
    async with session.post(f"{API_BASE}/{method}", json=payload or {}) as response:
        data = await response.json(content_type=None)
    if not data.get("ok"):
        raise TelegramAPIError(api_error_text(data))
    return data.get("result")


def urls_from_message(message: dict[str, Any]) -> list[str]:
    text = message.get("text") or message.get("caption") or ""
    found = {match.rstrip(TRAILING_URL_PUNCTUATION) for match in URL_RE.findall(text)}
    for key in ("entities", "caption_entities"):
        for entity in message.get(key) or []:
            if entity.get("type") == "text_link" and entity.get("url"):
                found.add(str(entity["url"]).rstrip(TRAILING_URL_PUNCTUATION))
            elif entity.get("type") == "url":
                # Telegram entity offsets and lengths use UTF-16 code units.
                encoded = text.encode("utf-16-le")
                start = int(entity.get("offset", 0)) * 2
                end = start + int(entity.get("length", 0)) * 2
                visible_url = encoded[start:end].decode("utf-16-le", errors="ignore")
                if visible_url:
                    found.add(visible_url.rstrip(TRAILING_URL_PUNCTUATION))
    return sorted(url for url in found if url)


def host_from_url(url: str) -> str:
    normalized = url if "://" in url else f"https://{url}"
    try:
        host = (urlsplit(normalized).hostname or "").rstrip(".").lower()
        return host.encode("idna").decode("ascii") if host else ""
    except (ValueError, UnicodeError):
        return ""


def inspect_url(url: str) -> tuple[int, list[str], str]:
    host = host_from_url(url)
    reasons: list[str] = []
    score = 0
    if not host:
        return 55, ["Havola manzilini to‘g‘ri aniqlab bo‘lmadi"], "noma’lum domen"
    if host.startswith("xn--") or ".xn--" in host:
        score += 45
        reasons.append("Domen xalqaro/punycode yozuvidan foydalanadi")
    try:
        ipaddress.ip_address(host.strip("[]"))
        score += 45
        reasons.append("Havola domen o‘rniga IP manzilga olib boradi")
    except ValueError:
        pass
    if host in SHORTENERS:
        score += 35
        reasons.append("Qisqartirilgan havola asl manzilni yashirishi mumkin")
    if "telegram" in host and host not in {"telegram.org", "t.me", "telegram.me"} and not host.endswith(".telegram.org"):
        score += 50
        reasons.append("Domen Telegram nomiga o‘xshatib yozilgan bo‘lishi mumkin")
    return min(score, 100), reasons, host


def analyze(message: dict[str, Any]) -> dict[str, Any] | None:
    reasons: list[str] = []
    score = 0
    document = message.get("document") or {}
    file_name = str(document.get("file_name") or "")
    mime = str(document.get("mime_type") or "").lower()
    is_apk = file_name.lower().endswith(".apk") or mime == "application/vnd.android.package-archive"
    if is_apk:
        score = max(score, 85)
        reasons.append("Android APK ilovasi yuborilgan; faylning xavfsizligi bu botda tekshirilmagan")
    elif file_name.lower().endswith((".exe", ".scr", ".msi", ".jar", ".bat", ".cmd")):
        score = max(score, 65)
        reasons.append("Ishga tushiriladigan dastur fayli yuborilgan")

    body = f"{message.get('text') or ''} {message.get('caption') or ''}".lower()
    matched_phrases = [phrase for phrase in SUSPICIOUS_PHRASES if phrase in body]
    if matched_phrases:
        score = min(100, score + 35)
        reasons.append("Xabarda kod, parol, pul yoki akkauntni shoshilinch tasdiqlashga undovchi ibora bor")

    link_results = []
    for url in urls_from_message(message):
        link_score, link_reasons, host = inspect_url(url)
        link_results.append({"host": host, "score": link_score, "reasons": link_reasons})
        if link_score:
            score = min(100, score + link_score)
            reasons.extend(link_reasons)

    if score < 35 and not link_results:
        return None
    sender = message.get("from") or {}
    sender_name = " ".join(part for part in (sender.get("first_name"), sender.get("last_name")) if part)
    if not sender_name:
        sender_name = "Telegram foydalanuvchisi"
    return {
        "score": min(score, 100),
        "level": (
            "YUQORI XAVF" if score >= 70 else
            "HAVOLA ESLATMASI" if score < 35 and link_results else
            "SHUBHALI"
        ),
        "reasons": list(dict.fromkeys(reasons)),
        "file_name": file_name if is_apk or file_name.lower().endswith((".exe", ".scr", ".msi", ".jar", ".bat", ".cmd")) else "",
        "links": link_results,
        "sender": sender_name,
    }


def business_deletion_reason(message: dict[str, Any], result: dict[str, Any]) -> str:
    """Return a reason only for actionable harmful items, not ordinary links/text."""
    document = message.get("document") or {}
    file_name = str(document.get("file_name") or result.get("file_name") or "").lower()
    mime = str(document.get("mime_type") or "").lower()
    if file_name.endswith(".apk") or mime == "application/vnd.android.package-archive":
        return "APK ilovasi"
    if file_name.endswith(EXECUTABLE_SUFFIXES) or mime in {
        "application/x-msdownload", "application/x-executable", "application/java-archive",
    }:
        return "ishga tushiriladigan fayl"
    if any(int(link.get("score", 0)) >= 35 for link in result.get("links", [])):
        return "shubhali yoki qisqartirilgan havola"
    return ""


def alert_message(result: dict[str, Any]) -> str:
    if result["level"] == "HAVOLA ESLATMASI":
        intro = "Xabarda havola bor. Bot saytni ochmaydi va uning xavfsizligini tasdiqlamaydi."
    else:
        intro = "Yangi xabarda xavf belgisi aniqlandi."
    lines = [f"⚠️ <b>{result['level']}</b>", intro, ""]
    lines.append(f"👤 Yuboruvchi: {html.escape(result['sender'])}")
    if result["file_name"]:
        lines.append(f"📎 Fayl: <code>{html.escape(result['file_name'])}</code>")
    for link in result["links"][:3]:
        lines.append(f"🔗 Domen: <code>{html.escape(link['host'])}</code>")
    lines.append("\n<b>Sabab:</b>")
    lines.extend(f"• {html.escape(reason)}" for reason in result["reasons"][:5])
    lines.append("\nNoma’lum APK’ni o‘rnatmang, havolada Telegram kodi yoki parolni kiritmang.")
    return "\n".join(lines)[:MAX_ALERT_TEXT]


def alert_keyboard(result: dict[str, Any]) -> dict[str, Any]:
    category = "apk" if result["file_name"].lower().endswith(".apk") else "link"
    return {"inline_keyboard": [[
        {"text": "Nega ogohlantirdi?", "callback_data": f"why:{category}"},
        {"text": "Xavfsizlik maslahati", "callback_data": "tips"},
    ]]}


async def handle_start(session: aiohttp.ClientSession, chat_id: int) -> None:
    await api(session, "sendMessage", {
        "chat_id": chat_id,
        "text": (
            "🛡 <b>Telegram Himoya botiga xush kelibsiz!</b>\n\n"
            "Men Telegram Business orqali ruxsat berilgan shaxsiy chatlardagi xabarlarni tekshiraman. "
            "Kiruvchi xabarda xavf belgisi topsam, sizga shu yerga xabar beraman. "
            "Sizning akkauntingizdan APK yoki shubhali havola yuborilsa, oluvchiga xabar ostida ogohlantirish yozaman.\n\n"
            "Ulash uchun Telegram sozlamalaridan <b>Telegram Business → Chatbots</b> bo‘limiga kiring, "
            "ushbu botni tanlang va chatlarni o‘qish hamda javob berish ruxsatini bering. Mavjud va yangi chatlar, "
            "kontaktlar va kontakt bo‘lmaganlarni tanlang. BotFather’da bot uchun Business Mode ham yoqilgan bo‘lishi kerak.\n\n"
            "Bot xabar matnlarini bazada saqlamaydi, fayllarni yuklab olmaydi va tashqi xizmatga yubormaydi."
        ),
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
        "reply_markup": MAIN_KEYBOARD,
    })


async def send_text(session: aiohttp.ClientSession, chat_id: int, text: str) -> None:
    await api(session, "sendMessage", {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
        "reply_markup": MAIN_KEYBOARD,
    })


def delete_mode_content(store: Store, owner_user_id: int) -> tuple[str, dict[str, Any]]:
    enabled = store.auto_delete_enabled(owner_user_id)
    status = "🟢 YOQILGAN" if enabled else "⚪ O‘CHIRILGAN"
    text = (
        f"🗑 <b>Zararli xabarlarni avtomatik o‘chirish: {status}</b>\n\n"
        "Yoqilganda bot ruxsat berilgan shaxsiy chatlardan kelgan APK/dastur fayllarini "
        "va aniq shubhali yoki qisqartirilgan havolalarni o‘chiradi, so‘ng sizga xabar beradi. "
        "Oddiy havolalar o‘chirilmaydi.\n\n"
        "Ishlashi uchun Telegram Business’da botga <b>qabul qilingan xabarlarni o‘chirish</b> "
        "huquqini bering. APK faylni antivirus kabi tekshirmaydi."
    )
    keyboard = {"inline_keyboard": [[
        {"text": "✅ Yoqish", "callback_data": "delete_mode:on"},
        {"text": "⏸ O‘chirish", "callback_data": "delete_mode:off"},
    ]]}
    return text, keyboard


async def send_delete_mode_menu(
    session: aiohttp.ClientSession, store: Store, chat_id: int,
) -> None:
    text, keyboard = delete_mode_content(store, chat_id)
    await api(session, "sendMessage", {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "reply_markup": keyboard,
        "disable_web_page_preview": True,
    })


async def handle_status(session: aiohttp.ClientSession, chat_id: int) -> None:
    try:
        info = await api(session, "getWebhookInfo")
        webhook_url = str(info.get("url") or "")
        pending = int(info.get("pending_update_count", 0))
        if webhook_url:
            mode = "Webhook sozlangan"
        else:
            mode = "Webhook yo‘q (lokal polling rejimi bo‘lishi mumkin)"
        lines = ["🛡 <b>Qalqon AI holati</b>", f"Server: ✅ ishlayapti", f"Qabul qilish: {mode}"]
        lines.append(f"Navbatdagi yangilanishlar: {pending}")
        last_error = str(info.get("last_error_message") or "").strip()
        if last_error:
            lines.append(f"Oxirgi webhook xatosi: {html.escape(last_error[:400])}")
        await send_text(session, chat_id, "\n".join(lines))
    except TelegramAPIError as exc:
        log.warning("Webhook holatini olishda xato: %s", exc)
        await send_text(session, chat_id, "Holatni tekshirib bo‘lmadi. Birozdan keyin /status ni qayta yuboring.")


async def handle_command(session: aiohttp.ClientSession, message: dict[str, Any]) -> None:
    chat_id = int(message["chat"]["id"])
    text = str(message.get("text") or "").strip()
    command = text.split(maxsplit=1)[0].split("@", 1)[0].lower() if text else ""
    if command == "/start":
        await handle_start(session, chat_id)
    elif command == "/status":
        await handle_status(session, chat_id)
    elif command == "/tips":
        await send_text(session, chat_id,
            "🔐 <b>Xavfsizlik maslahatlari</b>\n\n"
            "• Telegram login kodi va parolingizni hech kimga bermang.\n"
            "• Tanish bo‘lmagan odam yuborgan APK’ni o‘rnatmang.\n"
            "• Havola domenini tekshirmasdan ochmang va kod kiritmang.\n"
            "• Ikki bosqichli tasdiqlashni Telegram sozlamalarida yoqing.\n\n"
            "Ogohlantirish xavfni bildiruvchi belgi; bot faylni antivirus kabi tahlil qilmaydi.")
    elif command in {"/help", "/start_help"}:
        await send_text(session, chat_id,
            "🛡 <b>Qalqon AI</b>\n\n"
            "Pastdagi tugmalar orqali bot holatini ko‘ring, xavfsizlik maslahatlarini oling, botni qo‘lda tekshiring yoki uning ishlashini bilib oling.\n\n"
            "Bot ruxsat berilgan shaxsiy chatlardagi havola, APK va firibgarlikka o‘xshash iboralarni belgilaydi. "
            "Siz yuborgan shunday xabar topilsa, u xabar ostiga oluvchiga ogohlantirish yozadi. "
            "U faylni yuklab olmaydi va zararli ekanini tasdiqlamaydi.")


async def handle_keyboard_button(
    session: aiohttp.ClientSession, store: Store, message: dict[str, Any],
) -> bool:
    text = str(message.get("text") or "").strip()
    chat_id = int(message["chat"]["id"])
    if text == BUTTON_STATUS:
        await handle_status(session, chat_id)
    elif text == BUTTON_TIPS:
        await send_text(session, chat_id,
            "🔐 <b>Xavfsizlik maslahatlari</b>\n\n"
            "• Telegram login kodi va parolingizni hech kimga bermang.\n"
            "• Tanish bo‘lmagan odam yuborgan APK’ni o‘rnatmang.\n"
            "• Havola domenini tekshirmasdan ochmang va kod kiritmang.\n"
            "• Ikki bosqichli tasdiqlashni Telegram sozlamalarida yoqing.\n\n"
            "Ogohlantirish xavf belgisi borligini bildiradi; bot faylni antivirus kabi tahlil qilmaydi.")
    elif text == BUTTON_HELP:
        await handle_command(session, {**message, "text": "/help"})
    elif text == BUTTON_SCAN:
        await send_text(session, chat_id,
            "🔎 <b>Qo‘lda tekshirish</b>\n\n"
            "Shubhali xabarni shu botga forward qiling yoki havola, xabar matni yoxud APK faylini yuboring.\n\n"
            "Bot faqat ma’lum xavf belgilarini tekshiradi: havolani ochmaydi, faylni yuklab olmaydi va APK’ni antivirus kabi tahlil qilmaydi.")
    elif text == BUTTON_DELETE_MODE:
        await send_delete_mode_menu(session, store, chat_id)
    else:
        return False
    return True


def is_manual_scan_input(message: dict[str, Any]) -> bool:
    if message.get("document") or urls_from_message(message):
        return True
    body = f"{message.get('text') or ''} {message.get('caption') or ''}".lower()
    return any(phrase in body for phrase in SUSPICIOUS_PHRASES)


async def handle_manual_scan(session: aiohttp.ClientSession, message: dict[str, Any]) -> None:
    if (message.get("chat") or {}).get("type") != "private" or not is_manual_scan_input(message):
        return
    result = analyze(message)
    chat_id = int(message["chat"]["id"])
    if result:
        await api(session, "sendMessage", {
            "chat_id": chat_id,
            "text": "🔎 <b>Qo‘lda tekshiruv natijasi</b>\n\n" + alert_message(result),
            "parse_mode": "HTML",
            "reply_markup": alert_keyboard(result),
            "disable_web_page_preview": True,
        })
    else:
        await send_text(session, chat_id,
            "✅ Belgilangan xavf alomatlari topilmadi. Bu xabar yoki fayl mutlaqo xavfsiz degani emas: "
            "bot havolalarni ochmaydi va fayllarni antivirus kabi tekshirmaydi.")


def group_moderation_reason(message: dict[str, Any]) -> str:
    document = message.get("document") or {}
    file_name = str(document.get("file_name") or "").lower()
    mime = str(document.get("mime_type") or "").lower()
    if file_name.endswith(".apk") or mime == "application/vnd.android.package-archive":
        return "APK fayl"
    if file_name.endswith(EXECUTABLE_SUFFIXES) or mime in {
        "application/x-msdownload", "application/x-executable", "application/java-archive",
    }:
        return "ishga tushiriladigan fayl"
    if urls_from_message(message):
        return "havola"
    body = f"{message.get('text') or ''} {message.get('caption') or ''}".lower()
    if any(phrase in body for phrase in GROUP_SCAM_PHRASES):
        return "firibgarlikka o‘xshash matn"
    return ""


def group_sender_html(message: dict[str, Any]) -> str:
    sender = message.get("from") or {}
    username = str(sender.get("username") or "").strip()
    if username:
        return f"@{html.escape(username)}"
    sender_id = sender.get("id")
    name = " ".join(part for part in (sender.get("first_name"), sender.get("last_name")) if part)
    if sender_id and name:
        return f'<a href="tg://user?id={int(sender_id)}">{html.escape(name)}</a>'
    sender_chat = message.get("sender_chat") or {}
    if sender_chat.get("title"):
        return html.escape(str(sender_chat["title"]))
    return "Guruh a’zosi"


async def moderate_group_message(session: aiohttp.ClientSession, message: dict[str, Any]) -> None:
    reason = group_moderation_reason(message)
    if not reason:
        return
    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    message_id = message.get("message_id")
    if not chat_id or not message_id:
        return
    try:
        await api(session, "deleteMessage", {"chat_id": chat_id, "message_id": message_id})
    except TelegramAPIError as exc:
        log.warning("Guruhdagi xabarni o‘chira olmadim (chat=%s, message=%s): %s", chat_id, message_id, exc)
        return
    notice = (
        f"🛡 <b>Xabar o‘chirildi.</b>\n"
        f"{group_sender_html(message)} guruhga {html.escape(reason)} yubordi."
    )
    try:
        await api(session, "sendMessage", {
            "chat_id": chat_id,
            "text": notice,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        })
    except TelegramAPIError as exc:
        log.warning("Guruhga moderatsiya xabarini yubora olmadim (chat=%s): %s", chat_id, exc)


async def warn_recipient_about_suspicious_outgoing(
    session: aiohttp.ClientSession, message: dict[str, Any], connection_id: str,
    result: dict[str, Any],
) -> None:
    """Reply under a risky message sent from the connected business account."""
    chat_id = (message.get("chat") or {}).get("id")
    message_id = message.get("message_id")
    if not chat_id or not message_id:
        return

    file_name = result.get("file_name", "").lower()
    if file_name.endswith(".apk"):
        item = "APK fayl"
    elif file_name:
        item = "dastur fayli"
    elif result.get("links"):
        item = "havola"
    else:
        item = "shubhali matn"
    text = (
        "⚠️ <b>XAVFSIZLIK OGOHLANTIRISHI</b>\n\n"
        f"Ushbu xabarda {item} aniqlandi. Agar bu xabarni men yubormagan bo‘lsam, "
        "akkauntimga begona kirgan bo‘lishi mumkin. Iltimos, havolani ochmang, "
        "APK faylni yuklab olib o‘rnatmang. Men bilan boshqa ishonchli yo‘l orqali bog‘lanib aniqlashtiring."
    )
    try:
        await api(session, "sendMessage", {
            "business_connection_id": connection_id,
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
            "reply_parameters": {
                "message_id": message_id,
                "allow_sending_without_reply": True,
            },
        })
        log.info("Shubhali outgoing xabarga Business ogohlantirishi javob qilindi")
    except TelegramAPIError as exc:
        log.warning("Shubhali Business xabar ostiga ogohlantirish yuborilmadi: %s", exc)


async def delete_incoming_business_message(
    session: aiohttp.ClientSession, owner_chat_id: int, connection_id: str,
    message: dict[str, Any], reason: str,
) -> bool:
    chat_id = (message.get("chat") or {}).get("id")
    message_id = message.get("message_id")
    if not chat_id or not message_id:
        return False
    try:
        await api(session, "deleteBusinessMessages", {
            "business_connection_id": connection_id,
            "message_ids": [message_id],
        })
    except TelegramAPIError as exc:
        log.warning("Business xabarini o‘chira olmadim: %s", exc)
        try:
            await send_text(
                session,
                owner_chat_id,
                "⚠️ Xavfli xabar aniqlandi, lekin Telegram uni o‘chirishga ruxsat bermadi. "
                "Telegram Business → Chatbots → Qalqon AI bo‘limida "
                "<b>qabul qilingan xabarlarni o‘chirish</b> huquqini yoqing.",
            )
        except TelegramAPIError as notify_exc:
            log.warning("O‘chirish huquqi haqida egaga xabar yuborilmadi: %s", notify_exc)
        return False

    sender = message.get("from") or {}
    sender_name = " ".join(part for part in (sender.get("first_name"), sender.get("last_name")) if part)
    username = str(sender.get("username") or "").strip()
    sender_label = f"@{html.escape(username)}" if username else html.escape(sender_name or "Noma’lum foydalanuvchi")
    try:
        await send_text(
            session,
            owner_chat_id,
            "🗑 <b>Xavfli xabar o‘chirildi.</b>\n\n"
            f"Yuboruvchi: {sender_label}\nAniqlangan: {html.escape(reason)}\n\n"
            "APK yoki havolani bot ochmadi va faylni yuklab olmadi.",
        )
    except TelegramAPIError as exc:
        log.warning("O‘chirilgan xabar haqida egaga xabar yuborilmadi: %s", exc)
    log.info("Xavfli Business xabari o‘chirildi (%s)", reason)
    return True


async def process_update(session: aiohttp.ClientSession, store: Store, update: dict[str, Any]) -> None:
    message = update.get("message") or update.get("edited_message")
    if message:
        chat_type = (message.get("chat") or {}).get("type")
        if chat_type in {"group", "supergroup"}:
            await moderate_group_message(session, message)
            return
        text = str(message.get("text") or "")
        if text.startswith("/"):
            await handle_command(session, message)
        else:
            handled = await handle_keyboard_button(session, store, message)
            if not handled:
                await handle_manual_scan(session, message)
        return

    if "business_connection" in update:
        store.save_connection(update["business_connection"])
        log.info("Business ulanish holati yangilandi")
        return

    if "callback_query" in update:
        query = update["callback_query"]
        data = query.get("data", "")
        if data in {"delete_mode:on", "delete_mode:off"}:
            callback_message = query.get("message") or {}
            callback_chat = callback_message.get("chat") or {}
            callback_user_id = int((query.get("from") or {}).get("id", 0))
            callback_chat_id = int(callback_chat.get("id", 0))
            if (
                callback_chat.get("type") != "private"
                or callback_user_id != callback_chat_id
            ):
                await api(session, "answerCallbackQuery", {
                    "callback_query_id": query["id"],
                    "text": "Sozlama faqat shaxsiy bot chatida o‘zgartiriladi.",
                    "show_alert": True,
                })
                return
            enabled = data == "delete_mode:on"
            store.set_auto_delete(callback_user_id, enabled)
            text, keyboard = delete_mode_content(store, callback_user_id)
            await api(session, "answerCallbackQuery", {"callback_query_id": query["id"]})
            try:
                await api(session, "editMessageText", {
                    "chat_id": callback_chat_id,
                    "message_id": callback_message.get("message_id"),
                    "text": text,
                    "parse_mode": "HTML",
                    "reply_markup": keyboard,
                    "disable_web_page_preview": True,
                })
            except TelegramAPIError as exc:
                log.warning("Avto o‘chirish sozlamasi xabarini yangilay olmadim: %s", exc)
            return
        await api(session, "answerCallbackQuery", {"callback_query_id": query["id"]})
        if data.startswith("why:"):
            explanation = (
                "APK belgisi fayl Android ilovasi ekanini bildiradi, uning ichida zararli kod borligini bot tasdiqlamagan. "
                "Havola eslatmasi xabarda link borligini bildiradi. Bot linkni ochmaydi; qisqartirilgan, IP yoki soxta domenga o‘xshash belgilar bo‘lsa alohida ko‘rsatadi."
            )
            await api(session, "sendMessage", {"chat_id": query["message"]["chat"]["id"], "text": explanation})
        elif data == "tips":
            await api(session, "sendMessage", {
                "chat_id": query["message"]["chat"]["id"],
                "text": "Telegram login kodini hech kimga bermang. Noma’lum APK’ni o‘rnatmang. Havolani tekshirish uchun uni brauzerda ochmang — avval domen nomini sinchiklab ko‘ring.",
            })
        return

    message = update.get("business_message") or update.get("edited_business_message")
    if not message:
        return
    connection_id = message.get("business_connection_id")
    if not connection_id:
        return
    connection = store.connection(str(connection_id))
    if connection is None:
        try:
            info = await api(session, "getBusinessConnection", {"business_connection_id": connection_id})
            store.save_connection(info)
            connection = store.connection(str(connection_id))
        except TelegramAPIError as exc:
            log.warning("Business ulanish ma'lumotini olish imkoni bo‘lmadi: %s", exc)
            return
    if connection is None:
        return
    owner_chat_id, owner_user_id = connection

    # Business updates include incoming and outgoing messages. Warn the recipient
    # under risky messages sent from the owner's account; alert the owner about
    # risky incoming messages. Ignore messages generated by this bot to avoid loops.
    if (message.get("chat") or {}).get("type") != "private":
        return
    sender_id = (message.get("from") or {}).get("id")
    if message.get("sender_business_bot"):
        return

    result = analyze(message)
    if not result:
        return
    if sender_id == owner_user_id:
        await warn_recipient_about_suspicious_outgoing(
            session, message, str(connection_id), result
        )
        return

    if store.auto_delete_enabled(owner_user_id):
        reason = business_deletion_reason(message, result)
        if reason and await delete_incoming_business_message(
            session, owner_chat_id, str(connection_id), message, reason,
        ):
            return

    await api(session, "sendMessage", {
        "chat_id": owner_chat_id,
        "text": alert_message(result),
        "parse_mode": "HTML",
        "reply_markup": alert_keyboard(result),
        "disable_web_page_preview": True,
    })
    log.info("Xavfsizlik ogohlantirishi yuborildi (%s)", result["level"])


async def run_polling(session: aiohttp.ClientSession, store: Store) -> None:
    # Local development mode. Render free uses webhooks below.
    await api(session, "deleteWebhook", {"drop_pending_updates": False})
    offset = store.offset()
    while True:
        try:
            payload: dict[str, Any] = {"timeout": POLL_TIMEOUT, "allowed_updates": ALLOWED_UPDATES}
            if offset is not None:
                payload["offset"] = offset
            updates = await api(session, "getUpdates", payload)
            for update in updates:
                try:
                    await process_update(session, store, update)
                except (TelegramAPIError, KeyError, TypeError, ValueError) as exc:
                    log.warning("Yangilanishni qayta ishlashda xato: %s", exc)
                offset = int(update["update_id"]) + 1
                store.set_offset(offset)
        except asyncio.CancelledError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError, TelegramAPIError) as exc:
            log.warning("Telegram bilan aloqa uzildi; qayta uriniladi: %s", exc)
            await asyncio.sleep(3)


async def run_webhook(session: aiohttp.ClientSession, store: Store) -> None:
    external_url = os.environ.get("RENDER_EXTERNAL_URL", "").rstrip("/")
    secret = os.environ.get("WEBHOOK_SECRET", "").strip()
    if not external_url.startswith("https://"):
        raise SystemExit("Webhook rejimi uchun RENDER_EXTERNAL_URL (HTTPS) kerak.")
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", secret):
        raise SystemExit("WEBHOOK_SECRET 16-256 ta harf, raqam, _ yoki - bo‘lishi kerak.")

    async def health(_: web.Request) -> web.Response:
        return web.json_response({"ok": True})

    async def webhook(request: web.Request) -> web.Response:
        if not secrets.compare_digest(request.headers.get("X-Telegram-Bot-Api-Secret-Token", ""), secret):
            raise web.HTTPForbidden()
        try:
            update = await request.json()
            await process_update(session, store, update)
        except (TelegramAPIError, KeyError, TypeError, ValueError, aiohttp.ClientError) as exc:
            log.exception("Webhook yangilanishini qayta ishlashda xato: %s", exc)
            raise web.HTTPInternalServerError(text="Update processing failed") from exc
        return web.json_response({"ok": True})

    app = web.Application(client_max_size=1024 * 1024)
    app.router.add_get("/healthz", health)
    app.router.add_post(WEBHOOK_PATH, webhook)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", int(os.environ.get("PORT", "10000")))
    await site.start()
    await api(session, "setWebhook", {
        "url": f"{external_url}{WEBHOOK_PATH}",
        "secret_token": secret,
        "allowed_updates": ALLOWED_UPDATES,
        "drop_pending_updates": False,
    })
    log.info("Webhook ishga tushdi: %s%s", external_url, WEBHOOK_PATH)
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


async def run() -> None:
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN topilmadi. .env.example faylidan .env yarating va tokenni kiriting.")
    store = Store(DB_PATH)
    timeout = aiohttp.ClientTimeout(total=40, connect=15)
    connector = aiohttp.TCPConnector(limit=10, ttl_dns_cache=300)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        me = await api(session, "getMe")
        log.info("Bot ishga tushdi: @%s", me.get("username", "unknown"))
        try:
            await api(session, "deleteMyCommands")
        except TelegramAPIError as exc:
            log.warning("Bot menyusidagi eski buyruqlarni tozalash imkoni bo‘lmadi: %s", exc)
        if os.environ.get("RENDER_EXTERNAL_URL"):
            await run_webhook(session, store)
        else:
            await run_polling(session, store)


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        log.info("Bot to‘xtatildi")
