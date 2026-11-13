"""Telegram Business security assistant.

This starter monitors only business chats explicitly granted to the bot. It
does not download files or send message contents to third-party services.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict, deque
import html
import hashlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import secrets
import time
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


os.umask(0o077)
load_dotenv()
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))
DB_PATH = Path(os.environ.get("DATABASE_PATH", str(DATA_DIR / "himoya.sqlite3")))
API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}"
POLL_TIMEOUT = 30
MAX_ALERT_TEXT = 3500
WEBHOOK_PATH = "/telegram/webhook"
MAX_WEBHOOK_BYTES = 262144
MAX_PENDING_UPDATES = 32
BUTTON_STATUS = "📊 Bot holati"
BUTTON_TIPS = "🔐 Xavfsizlik maslahatlari"
BUTTON_SCAN = "🔎 Xabarni tekshirish"
BUTTON_HELP = "ℹ️ Qanday ishlaydi"
BUTTON_DELETE_MODE = "🗑 Avto o‘chirish sozlamasi"
BUTTON_OUTGOING_WARNING = "⚠️ Yuborilgan xabar ogohlantirishi"
BUTTON_UNKNOWN_SENDER = "🌍 Xalqaro raqam ogohlantirishi"
BUTTON_PHOTO_TEST = "🧪 O‘z rasmlarimni sinash"
MAIN_KEYBOARD = {
    "keyboard": [
        [BUTTON_STATUS, BUTTON_TIPS],
        [BUTTON_SCAN, BUTTON_HELP],
        [BUTTON_DELETE_MODE],
        [BUTTON_OUTGOING_WARNING],
        [BUTTON_UNKNOWN_SENDER],
        [BUTTON_PHOTO_TEST],
    ],
    "resize_keyboard": True,
    "is_persistent": True,
    "one_time_keyboard": False,
    "selective": False,
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


def redact_secrets(text: str) -> str:
    for value in (BOT_TOKEN, os.environ.get("WEBHOOK_SECRET", "")):
        if value:
            text = text.replace(value, "[REDACTED]")
    return re.sub(r"(?<![0-9])[0-9]{6,}:[A-Za-z0-9_-]{20,}", "[REDACTED]", text)


class SafeLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact_secrets(super().format(record))


for handler in logging.getLogger().handlers:
    handler.setFormatter(SafeLogFormatter("%(asctime)s %(levelname)s %(message)s"))


class InteractionLimiter:
    """Bound memory and limit direct bot commands; never drop Business protection updates."""

    def __init__(self, capacity: int = 20, period: float = 60, max_keys: int = 10000) -> None:
        self.capacity, self.period, self.max_keys = capacity, period, max_keys
        self.entries: OrderedDict[tuple[str, int], deque[float]] = OrderedDict()

    def allow(self, key: tuple[str, int]) -> bool:
        now = time.monotonic()
        while self.entries and next(iter(self.entries.values()))[-1] <= now - self.period:
            self.entries.popitem(last=False)
        events = self.entries.pop(key, deque())
        while events and events[0] <= now - self.period:
            events.popleft()
        allowed = len(events) < self.capacity
        if allowed:
            events.append(now)
        self.entries[key] = events
        while len(self.entries) > self.max_keys:
            self.entries.popitem(last=False)
        return allowed


PRIVATE_LIMITER = InteractionLimiter()

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


class TelegramTemporaryError(TelegramAPIError):
    """Transport/rate-limit failures must remain retryable by Telegram."""


class Store:
    """Persist only connection routing and update offset, never message text."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path)
        path.chmod(0o600)
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("PRAGMA trusted_schema=OFF")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS processed_updates ("
            "update_id INTEGER PRIMARY KEY, processed_at INTEGER NOT NULL)"
        )
        self.db.execute("CREATE INDEX IF NOT EXISTS processed_updates_age ON processed_updates(processed_at)")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS photo_tests ("
            "token_hash TEXT PRIMARY KEY, owner INTEGER NOT NULL, sender INTEGER, "
            "expires INTEGER NOT NULL, approved INTEGER NOT NULL DEFAULT 0, remaining INTEGER NOT NULL DEFAULT 1)"
        )
        self.db.execute("DELETE FROM processed_updates WHERE processed_at < ?", (int(time.time()) - 172800,))
        self._processed_since_cleanup = 0
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
            "owner_user_id INTEGER PRIMARY KEY, auto_delete_harmful INTEGER NOT NULL DEFAULT 0, "
            "outgoing_warning INTEGER NOT NULL DEFAULT 0, unknown_sender_warning INTEGER NOT NULL DEFAULT 1)"
        )
        setting_columns = {row[1] for row in self.db.execute("PRAGMA table_info(user_settings)")}
        if "outgoing_warning" not in setting_columns:
            self.db.execute(
                "ALTER TABLE user_settings ADD COLUMN outgoing_warning INTEGER NOT NULL DEFAULT 0"
            )
        if "unknown_sender_warning" not in setting_columns:
            self.db.execute(
                "ALTER TABLE user_settings ADD COLUMN unknown_sender_warning INTEGER NOT NULL DEFAULT 1"
            )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS sender_profiles ("
            "owner_user_id INTEGER NOT NULL, sender_user_id INTEGER NOT NULL, "
            "trusted INTEGER NOT NULL DEFAULT 0, foreign_number_alerted INTEGER NOT NULL DEFAULT 0, "
            "PRIMARY KEY(owner_user_id, sender_user_id))"
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
        enabled = int(bool(connection.get("is_enabled", False)))
        if enabled:
            self.db.execute(
                "UPDATE connections SET enabled=0 WHERE owner_user_id=? AND connection_id<>?",
                (int(owner_user_id), str(connection_id)),
            )
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

    def active_connection_id(self, owner_user_id: int) -> str | None:
        row = self.db.execute(
            "SELECT connection_id FROM connections WHERE owner_user_id=? AND enabled=1 ORDER BY rowid DESC LIMIT 1",
            (int(owner_user_id),),
        ).fetchone()
        return str(row[0]) if row else None

    def set_auto_delete(self, owner_user_id: int, enabled: bool) -> None:
        self.db.execute(
            "INSERT INTO user_settings(owner_user_id, auto_delete_harmful) VALUES(?,?) "
            "ON CONFLICT(owner_user_id) DO UPDATE SET auto_delete_harmful=excluded.auto_delete_harmful",
            (int(owner_user_id), int(enabled)),
        )
        self.db.commit()

    def outgoing_warning_enabled(self, owner_user_id: int) -> bool:
        row = self.db.execute(
            "SELECT outgoing_warning FROM user_settings WHERE owner_user_id=?",
            (int(owner_user_id),),
        ).fetchone()
        return bool(row[0]) if row else False

    def set_outgoing_warning(self, owner_user_id: int, enabled: bool) -> None:
        self.db.execute(
            "INSERT INTO user_settings(owner_user_id, outgoing_warning) VALUES(?,?) "
            "ON CONFLICT(owner_user_id) DO UPDATE SET outgoing_warning=excluded.outgoing_warning",
            (int(owner_user_id), int(enabled)),
        )
        self.db.commit()

    def unknown_sender_warning_enabled(self, owner_user_id: int) -> bool:
        row = self.db.execute(
            "SELECT unknown_sender_warning FROM user_settings WHERE owner_user_id=?",
            (int(owner_user_id),),
        ).fetchone()
        return bool(row[0]) if row else True

    def set_unknown_sender_warning(self, owner_user_id: int, enabled: bool) -> None:
        self.db.execute(
            "INSERT INTO user_settings(owner_user_id, unknown_sender_warning) VALUES(?,?) "
            "ON CONFLICT(owner_user_id) DO UPDATE SET unknown_sender_warning=excluded.unknown_sender_warning",
            (int(owner_user_id), int(enabled)),
        )
        self.db.commit()

    def observe_sender(self, owner_user_id: int, sender_user_id: int) -> tuple[bool, bool]:
        cursor = self.db.execute(
            "INSERT OR IGNORE INTO sender_profiles(owner_user_id, sender_user_id) VALUES(?,?)",
            (int(owner_user_id), int(sender_user_id)),
        )
        self.db.commit()
        row = self.db.execute(
            "SELECT trusted FROM sender_profiles WHERE owner_user_id=? AND sender_user_id=?",
            (int(owner_user_id), int(sender_user_id)),
        ).fetchone()
        return cursor.rowcount == 1, bool(row[0]) if row else False

    def trust_sender(self, owner_user_id: int, sender_user_id: int) -> None:
        self.db.execute(
            "INSERT INTO sender_profiles(owner_user_id, sender_user_id, trusted) VALUES(?,?,1) "
            "ON CONFLICT(owner_user_id, sender_user_id) DO UPDATE SET trusted=1",
            (int(owner_user_id), int(sender_user_id)),
        )
        self.db.commit()

    def mark_foreign_number_alerted(self, owner_user_id: int, sender_user_id: int) -> bool:
        cursor = self.db.execute(
            "UPDATE sender_profiles SET foreign_number_alerted=1 "
            "WHERE owner_user_id=? AND sender_user_id=? AND foreign_number_alerted=0",
            (int(owner_user_id), int(sender_user_id)),
        )
        self.db.commit()
        return cursor.rowcount == 1

    def foreign_number_alerted(self, owner_user_id: int, sender_user_id: int) -> bool:
        row = self.db.execute(
            "SELECT foreign_number_alerted FROM sender_profiles WHERE owner_user_id=? AND sender_user_id=?",
            (int(owner_user_id), int(sender_user_id)),
        ).fetchone()
        return bool(row[0]) if row else False

    def set_offset(self, offset: int) -> None:
        self.db.execute(
            "INSERT INTO state(key,value) VALUES('update_offset',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(offset),)
        )
        self.db.commit()

    def new_photo_test(self, owner: int) -> str:
        token = secrets.token_urlsafe(24)
        self.db.execute("DELETE FROM photo_tests WHERE owner=? OR expires<=?", (owner, int(time.time())))
        self.db.execute(
            "INSERT INTO photo_tests(token_hash,owner,expires) VALUES(?,?,?)",
            (hashlib.sha256(token.encode()).hexdigest(), owner, int(time.time()) + 900),
        )
        self.db.commit()
        return token

    def photo_invite(self, token: str) -> tuple[int, int | None, int] | None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{32}", token):
            return None
        row = self.db.execute(
            "SELECT owner,sender,approved FROM photo_tests WHERE token_hash=? AND expires>? AND remaining=1",
            (hashlib.sha256(token.encode()).hexdigest(), int(time.time())),
        ).fetchone()
        return (int(row[0]), int(row[1]) if row[1] else None, int(row[2])) if row else None

    def approve_photo_test(self, token: str, sender: int) -> int | None:
        invite = self.photo_invite(token)
        if not invite or invite[0] == sender or invite[2]:
            return None
        cursor = self.db.execute(
            "UPDATE photo_tests SET sender=?,approved=1 WHERE token_hash=? AND approved=0 AND remaining=1 AND expires>?",
            (sender, hashlib.sha256(token.encode()).hexdigest(), int(time.time())),
        )
        self.db.commit()
        return invite[0] if cursor.rowcount == 1 else None

    def claim_photo_test(self, owner: int, sender: int) -> str | None:
        row = self.db.execute(
            "SELECT token_hash FROM photo_tests WHERE owner=? AND sender=? AND approved=1 AND remaining=1 AND expires>?",
            (owner, sender, int(time.time())),
        ).fetchone()
        if not row:
            return None
        cursor = self.db.execute("UPDATE photo_tests SET remaining=0 WHERE token_hash=? AND remaining=1", (row[0],))
        self.db.commit()
        return str(row[0]) if cursor.rowcount == 1 else None

    def retry_photo_test(self, token_hash: str) -> None:
        self.db.execute("UPDATE photo_tests SET remaining=1 WHERE token_hash=? AND expires>?", (token_hash, int(time.time())))
        self.db.commit()

    def stop_photo_tests(self, user_id: int) -> None:
        self.db.execute("UPDATE photo_tests SET remaining=0 WHERE owner=? OR sender=?", (user_id, user_id))
        self.db.commit()

    def decline_photo_test(self, token: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{32}", token):
            return
        self.db.execute(
            "UPDATE photo_tests SET remaining=0 WHERE token_hash=? AND approved=0",
            (hashlib.sha256(token.encode()).hexdigest(),),
        )
        self.db.commit()

    def update_processed(self, update_id: int) -> bool:
        return self.db.execute(
            "SELECT 1 FROM processed_updates WHERE update_id=?", (update_id,)
        ).fetchone() is not None

    def mark_update_processed(self, update_id: int) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO processed_updates VALUES(?,?)", (update_id, int(time.time())),
        )
        self._processed_since_cleanup += 1
        if self._processed_since_cleanup >= 128:
            self.db.execute("DELETE FROM processed_updates WHERE processed_at < ?", (int(time.time()) - 172800,))
            self._processed_since_cleanup = 0
        self.db.commit()

    def offset(self) -> int | None:
        row = self.db.execute("SELECT value FROM state WHERE key='update_offset'").fetchone()
        return int(row[0]) if row else None


def api_error_text(data: dict[str, Any]) -> str:
    description = redact_secrets(str(data.get("description", "noma’lum xato")))
    description = " ".join(description.split())[:250]
    return f"Telegram API xatosi ({data.get('error_code', '?')}): {description}"


async def api(session: aiohttp.ClientSession, method: str, payload: dict[str, Any] | None = None) -> Any:
    if not re.fullmatch(r"[A-Za-z]+", method):
        raise TelegramAPIError("Telegram API metodi noto‘g‘ri")
    if (
        method == "sendMessage" and payload
        and type(payload.get("chat_id")) is int and payload["chat_id"] > 0
        and not payload.get("business_connection_id") and "reply_markup" not in payload
    ):
        payload = {**payload, "reply_markup": MAIN_KEYBOARD}
    try:
        async with session.post(f"{API_BASE}/{method}", json=payload or {}, allow_redirects=False) as response:
            if response.status == 429 or response.status >= 500:
                raise TelegramTemporaryError(f"Telegram vaqtinchalik xatosi ({response.status})")
            if 300 <= response.status < 400:
                raise TelegramAPIError("Telegram API kutilmagan yo‘naltirish qaytardi")
            body = bytearray()
            async for chunk in response.content.iter_chunked(65536):
                body.extend(chunk)
                if len(body) > 2097152:
                    raise TelegramAPIError("Telegram API javobi juda katta")
            data = json.loads(body)
            if not isinstance(data, dict):
                raise TelegramAPIError("Telegram API javobi noto‘g‘ri")
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, UnicodeError) as exc:
        # Network exception strings can contain the bot-token-bearing request URL.
        raise TelegramTemporaryError(f"Telegram bilan aloqa xatosi ({type(exc).__name__})") from None
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


def has_foreign_international_number(message: dict[str, Any]) -> bool:
    """Detect an explicit international number other than +998 or +7."""
    text = " ".join(str(message.get(key) or "") for key in ("text", "caption"))
    contact = message.get("contact") or {}
    if contact.get("phone_number"):
        text += " " + str(contact["phone_number"])
    for match in re.finditer(r"(?<!\w)\+\s*\d[\d\s().-]{5,24}", text):
        digits = re.sub(r"\D", "", match.group())
        if not 7 <= len(digits) <= 15:
            continue
        if digits.startswith(("998", "7")):
            continue
        return True
    return False


def sender_display(message: dict[str, Any]) -> str:
    sender = message.get("from") or {}
    username = str(sender.get("username") or "").strip()
    if username:
        return "@" + html.escape(username)
    name = " ".join(part for part in (sender.get("first_name"), sender.get("last_name")) if part)
    return html.escape(name or "Telegram foydalanuvchisi")


def foreign_number_alert(message: dict[str, Any]) -> str:
    return (
        "🌍 <b>Xalqaro raqam ogohlantirishi</b>\n\n"
        f"Yuboruvchi: {sender_display(message)}\n"
        "Xabarda +998 va +7 dan boshqa xalqaro telefon raqami ko‘rindi. "
        "Bu yuboruvchining o‘z raqami ekanini anglatmaydi.\n\n"
        "Shaxsni boshqa yo‘l bilan tekshirib oling."
    )


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
    """Delete executable files and every detected link when the owner enables the mode."""
    document = message.get("document") or {}
    file_name = str(document.get("file_name") or result.get("file_name") or "").lower()
    mime = str(document.get("mime_type") or "").lower()
    if file_name.endswith(".apk") or mime == "application/vnd.android.package-archive":
        return "APK ilovasi"
    if file_name.endswith(EXECUTABLE_SUFFIXES) or mime in {
        "application/x-msdownload", "application/x-executable", "application/java-archive",
    }:
        return "ishga tushiriladigan fayl"
    if urls_from_message(message):
        return "havola"
    return ""


def business_outgoing_warning_reason(message: dict[str, Any], result: dict[str, Any]) -> str:
    document = message.get("document") or {}
    file_name = str(document.get("file_name") or result.get("file_name") or "").lower()
    mime = str(document.get("mime_type") or "").lower()
    if file_name.endswith(".apk") or mime == "application/vnd.android.package-archive":
        return "APK"
    if any(int(link.get("score", 0)) >= 35 for link in result.get("links", [])):
        return "shubhali havola"
    return ""


def alert_message(result: dict[str, Any]) -> str:
    if result["level"] == "HAVOLA ESLATMASI":
        intro = "Xabarda havola bor. Bot saytni ochmaydi va uning xavfsizligini tasdiqlamaydi."
    else:
        intro = "Yangi xabarda xavf belgisi aniqlandi."
    lines = [f"⚠️ <b>{result['level']}</b>", intro, ""]
    lines.append(f"👤 Yuboruvchi: {html.escape(result['sender'][:128])}")
    if result["file_name"]:
        lines.append(f"📎 Fayl: <code>{html.escape(result['file_name'][:256])}</code>")
    for link in result["links"][:3]:
        lines.append(f"🔗 Domen: <code>{html.escape(link['host'][:253])}</code>")
    lines.append("\n<b>Sabab:</b>")
    lines.extend(f"• {html.escape(reason[:256])}" for reason in result["reasons"][:5])
    lines.append("\nNoma’lum APK’ni o‘rnatmang, havolada Telegram kodi yoki parolni kiritmang.")
    # Bound visible fields before escaping; slicing HTML can break tags/entities.
    return "\n".join(lines)


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
            "🛡 <b>Qalqon AI — Telegram himoyasi</b>\n"
            "APK, havola va firibgarlik belgilarini kuzatishga yordam beradi.\n\n"
            "<b>Afzalliklari</b>\n"
            "• Ruxsat berilgan shaxsiy chatlardagi xavf belgilarini aniqlab, sizga ogohlantirish yuboradi.\n"
            "• <b>🗑 Avto o‘chirish sozlamasi</b> orqali APK/dastur fayllari va barcha havolali xabarlarni o‘chirishni o‘zingiz yoqasiz yoki o‘chirasiz.\n"
            "• <b>⚠️ Yuborilgan xabar ogohlantirishi</b> orqali akkauntingizdan APK yoki shubhali havola ketsa, oluvchiga ogohlantirish yozishni yoqasiz yoki o‘chirasiz.\n"
            "• <b>🌍 Xalqaro raqam ogohlantirishi</b> xabardagi +998/+7 dan boshqa xalqaro raqamni bildiradi.\n"
            "• Guruhda APK, dastur fayli va havolalarni o‘chirib, guruhga xabar beradi.\n\n"
            "<b>Qanday yoqiladi?</b>\n"
            "1. Telegram <b>Sozlamalar → Telegram Business → Chatbots</b>ga kiring, Qalqon AI’ni tanlang va kerakli chatlarga ruxsat bering.\n"
            "2. Pastdagi sozlamalardan kerakli rejimni yoqing. Avto o‘chirish uchun <b>barcha xabarlarni o‘chirish</b>, yuborilgan xabar ogohlantirishi uchun <b>Javob berish</b> huquqini bering.\n"
            "3. Guruh himoyasi uchun botni guruhga qo‘shib, administrator qiling va <b>Delete Messages</b> huquqini bering.\n\n"
            "⚠️ Bot APK faylni antivirus kabi tekshirmaydi; xavf belgilariga qarab ogohlantiradi. Xabar matnlari bazada saqlanmaydi, fayllar yuklab olinmaydi."
            " Telegram odatda yuboruvchining telefon raqamini botga ko‘rsatmaydi; faqat xabarda ochiq yozilgan yoki kontakt qilib yuborilgan raqam tekshiriladi."
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


async def send_photo_test_menu(session: aiohttp.ClientSession, chat_id: int) -> None:
    await send_text(session, chat_id,
        "🧪 <b>Ikki akkaunt bilan rasm sinovi</b>\n\n"
        "Bu rejim odatda o‘chiq. Sinov havolasini o‘zingizning ikkinchi akkauntingizda ochib, "
        "rasm nusxasini birinchi akkauntga yuborishga alohida rozilik bering.\n\n"
        "Sinov 15 daqiqa va faqat bitta rasm uchun amal qiladi. Rasm botga Telegram API orqali "
        "kelgan bo‘lsa, nusxasi yuboriladi. Bir martalik rasmni Telegram botga bermasligi mumkin; "
        "bu rejim Telegram cheklovlarini chetlab o‘tmaydi. Fayl serverga yuklab olinmaydi.")
    await api(session, "sendMessage", {
        "chat_id": chat_id, "text": "Sinovni boshqarish:",
        "reply_markup": {"inline_keyboard": [[
            {"text": "🔗 Sinov havolasini olish", "callback_data": "photo_test:new"},
        ], [{"text": "⏹ Sinovni to‘xtatish", "callback_data": "photo_test:stop"}]]},
    })


async def open_photo_test_invite(
    session: aiohttp.ClientSession, store: Store, message: dict[str, Any],
) -> bool:
    parts = str(message.get("text") or "").split()
    if len(parts) != 2 or parts[0].split("@", 1)[0] != "/start" or not parts[1].startswith("photo_test_"):
        return False
    actor = int(message["chat"]["id"])
    token = parts[1][len("photo_test_"):]
    invite = store.photo_invite(token)
    if not invite or invite[2] or invite[0] == actor:
        await send_text(session, actor, "Sinov havolasi eskirgan, ishlatilgan yoki boshqa akkauntda ochilishi kerak.")
        return True
    await send_text(session, actor,
        "🧪 <b>Rasm nusxasini yuborishga rozilik</b>\n\n"
        f"Qabul qiluvchi akkaunt ID: <code>{invite[0]}</code>\n\n"
        "Tasdiqlasangiz, shu akkauntga keyin yuboradigan <b>bitta rasmingiz</b> bot orqali "
        "uning shaxsiy bot chatiga nusxalanishi mumkin. Sinov 15 daqiqada tugaydi. "
        "Faqat ikkala akkaunt ham sizniki bo‘lsa va shu nusxani olishga rozi bo‘lsangiz tasdiqlang.")
    await api(session, "sendMessage", {
        "chat_id": actor, "text": "Rasmingiz nusxalanishiga rozimisiz?",
        "reply_markup": {"inline_keyboard": [[
            {"text": "✅ Roziman", "callback_data": f"photo_test:yes:{token}"},
            {"text": "❌ Yo‘q", "callback_data": f"photo_test:no:{token}"},
        ]]},
    })
    return True


async def handle_photo_test_callback(
    session: aiohttp.ClientSession, store: Store, query: dict[str, Any],
) -> None:
    actor = int(query["from"]["id"])
    data = str(query.get("data") or "")
    # Acknowledge a real Telegram callback before changing consent state.
    await api(session, "answerCallbackQuery", {"callback_query_id": query["id"]})
    if data == "photo_test:stop":
        store.stop_photo_tests(actor)
        await send_text(session, actor, "⏹ Siz qatnashgan rasm sinovlari to‘xtatildi.")
    elif data.startswith("photo_test:no:"):
        store.decline_photo_test(data[len("photo_test:no:"):])
        await send_text(session, actor, "⏹ Rozilik berilmadi. Sinov bekor qilindi.")
    elif data == "photo_test:new":
        if not store.active_connection_id(actor):
            await send_text(session, actor, "Avval shu akkauntga botni Telegram Business orqali ulang.")
            return
        me = await api(session, "getMe")
        username = str(me.get("username") or "")
        if not re.fullmatch(r"[A-Za-z0-9_]{5,32}", username):
            await send_text(session, actor, "Bot havolasini yaratib bo‘lmadi. Keyinroq urinib ko‘ring.")
            return
        token = store.new_photo_test(actor)
        await send_text(session, actor,
            "🔗 Havolani <b>o‘zingizning ikkinchi akkauntingizda</b> ochib, rozilikni tasdiqlang:\n\n"
            f"https://t.me/{username}?start=photo_test_{token}\n\n"
            "Keyin ikkinchi akkauntdan shu Business akkauntingizga bitta rasm yuboring. "
            "Bu chat botga ruxsat berilgan chatlar ichida bo‘lishi kerak. Havola 15 daqiqada eskiradi.")
    elif data.startswith("photo_test:yes:"):
        token = data[len("photo_test:yes:"):]
        owner = store.approve_photo_test(token, actor)
        if owner is None:
            await send_text(session, actor, "Havola eskirgan yoki ishlatilgan. Yangi sinov havolasi kerak.")
            return
        await send_text(session, actor, "✅ Rozilik qayd etildi. Endi o‘zingizning birinchi akkauntingizga bitta sinov rasmi yuboring.")
        await send_text(session, owner,
            f"✅ <code>{actor}</code> akkaunti bitta rasm nusxasi uchun rozilik berdi. "
            "Sinov havola yaratilganidan 15 daqiqa o‘tgach avtomatik tugaydi.")


async def try_consented_photo_test(
    session: aiohttp.ClientSession, store: Store, message: dict[str, Any],
    owner_chat_id: int, owner_user_id: int,
) -> None:
    photos = message.get("photo")
    sender = (message.get("from") or {}).get("id")
    if not isinstance(photos, list) or not photos or not sender or sender == owner_user_id:
        return
    token_hash = store.claim_photo_test(owner_user_id, int(sender))
    if not token_hash:
        return
    file_id = photos[-1].get("file_id")
    if not isinstance(file_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{10,1024}", file_id):
        await send_text(session, owner_chat_id, "🧪 Rasm xabari keldi, lekin Telegram qayta yuborish uchun fayl ID bermadi. Sinov tugadi.")
        return
    try:
        await api(session, "sendPhoto", {
            "chat_id": owner_chat_id, "photo": file_id,
            "caption": "🧪 Ikki akkaunt roziligi bilan sinov nusxasi. Sinov tugadi.",
            "reply_markup": MAIN_KEYBOARD,
        })
    except TelegramTemporaryError:
        store.retry_photo_test(token_hash)
        raise
    except TelegramAPIError:
        await send_text(session, owner_chat_id,
            "🧪 Telegram bu rasmni qayta yuborishga ruxsat bermadi. Rasm serverga yuklab olinmadi. Sinov tugadi.")


def delete_mode_content(store: Store, owner_user_id: int) -> tuple[str, dict[str, Any]]:
    enabled = store.auto_delete_enabled(owner_user_id)
    status = "🟢 YOQILGAN" if enabled else "⚪ O‘CHIRILGAN"
    text = (
        f"🗑 <b>Zararli xabarlarni avtomatik o‘chirish: {status}</b>\n\n"
        "Yoqilganda bot ruxsat berilgan shaxsiy chatlardan kelgan APK/dastur fayllarini "
        "va barcha havolali xabarlarni o‘chiradi, so‘ng sizga xabar beradi. "
        "Oddiy, qisqartirilgan va matn ichiga yashirilgan havolalar ham o‘chiriladi.\n\n"
        "Ishlashi uchun Telegram Business’da botga <b>barcha xabarlarni o‘chirish</b> "
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
    await send_text(session, chat_id, "🗑 <b>Avto o‘chirish sozlamasi</b>")
    allowed, permission_text = await check_delete_permission(session, store, chat_id)
    text += "\n\n" + permission_text
    await api(session, "sendMessage", {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "reply_markup": keyboard,
        "disable_web_page_preview": True,
    })


async def check_delete_permission(
    session: aiohttp.ClientSession, store: Store, owner_user_id: int,
) -> tuple[bool, str]:
    connection_id = store.active_connection_id(owner_user_id)
    if not connection_id:
        return False, "🔌 Botga Telegram Business ulanishi kelmagan. Botni akkauntingizga ulang yoki qayta ulang."
    try:
        connection = await api(session, "getBusinessConnection", {"business_connection_id": connection_id})
        store.save_connection(connection)
    except TelegramAPIError as exc:
        if isinstance(exc, TelegramTemporaryError):
            raise
        log.warning("O‘chirish ruxsatini tekshira olmadim: %s", exc)
        return False, "⚠️ Ulanish ruxsatini tekshirib bo‘lmadi. Telegram Business’da botni qayta ulang."
    if not connection.get("is_enabled"):
        return False, "🔌 Telegram Business ulanishi o‘chirilgan. Botni qayta ulang."
    if not (connection.get("rights") or {}).get("can_delete_all_messages"):
        return False, (
            "🔴 Telegram’da <b>Barcha xabarlarni o‘chirish / Delete all messages</b> ruxsati yo‘q. "
            "Sozlamalar → Telegram Business → Chatbots → Qalqon AI bo‘limida shu ruxsatni yoqing "
            "va saqlang. Faqat bot yuborgan xabarlarni o‘chirish ruxsati yetmaydi."
        )
    return True, "🟢 Telegram’dagi barcha xabarlarni o‘chirish ruxsati mavjud."


def outgoing_warning_content(store: Store, owner_user_id: int) -> tuple[str, dict[str, Any]]:
    enabled = store.outgoing_warning_enabled(owner_user_id)
    status = "🟢 YOQILGAN" if enabled else "⚪ O‘CHIRILGAN"
    text = (
        f"⚠️ <b>Yuborilgan xabar ogohlantirishi: {status}</b>\n\n"
        "Yoqilganda akkauntingizdan APK yoki aniq shubhali havola yuborilsa, bot uning ostiga "
        "oluvchiga siz tanlagan ogohlantirishni yozishga urinadi. Oddiy xabarlarga javob qo‘shilmaydi.\n\n"
        "Buning uchun Telegram Business’da <b>Javob berish</b> huquqi kerak. Telegram ayrim chatlarda "
        "javobni cheklashi mumkin; bunday holatda ogohlantirish yetib bormasligi mumkin."
    )
    keyboard = {"inline_keyboard": [[
        {"text": "✅ Yoqish", "callback_data": "outgoing_warning:on"},
        {"text": "⏸ O‘chirish", "callback_data": "outgoing_warning:off"},
    ]]}
    return text, keyboard


async def send_outgoing_warning_menu(
    session: aiohttp.ClientSession, store: Store, chat_id: int,
) -> None:
    text, keyboard = outgoing_warning_content(store, chat_id)
    await send_text(session, chat_id, "⚠️ <b>Yuborilgan xabar ogohlantirishi</b>")
    await api(session, "sendMessage", {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "reply_markup": keyboard,
        "disable_web_page_preview": True,
    })


def unknown_sender_content(store: Store, owner_user_id: int) -> tuple[str, dict[str, Any]]:
    enabled = store.unknown_sender_warning_enabled(owner_user_id)
    status = "🟢 YOQILGAN" if enabled else "⚪ O‘CHIRILGAN"
    text = (
        f"🌍 <b>Xalqaro raqam ogohlantirishi: {status}</b>\n\n"
        "Xabarda ochiq ko‘rsatilgan yoki kontakt sifatida yuborilgan +raqam aniqlansa, +998 va +7 dan "
        "boshqa xalqaro raqamlar haqida ham bir marta xabar beradi. Bu raqam yuboruvchining o‘ziga tegishli "
        "bo‘lishi shart emas. Telegram botga yuboruvchining odatda yashirin telefon raqamini bermaydi."
    )
    keyboard = {"inline_keyboard": [[
        {"text": "✅ Yoqish", "callback_data": "unknown_sender:on"},
        {"text": "⏸ O‘chirish", "callback_data": "unknown_sender:off"},
    ]]}
    return text, keyboard


async def send_unknown_sender_menu(
    session: aiohttp.ClientSession, store: Store, chat_id: int,
) -> None:
    text, keyboard = unknown_sender_content(store, chat_id)
    await send_text(session, chat_id, "🌍 <b>Xalqaro raqam ogohlantirishi</b>")
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
            lines.append("⚠️ Telegram webhook yetkazishda xato qayd etgan. Server holatini tekshirish kerak.")
        await send_text(session, chat_id, "\n".join(lines))
    except TelegramAPIError as exc:
        if isinstance(exc, TelegramTemporaryError):
            raise
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
            "Yuborilgan xabar ogohlantirishi va avto o‘chirish rejimlarini tugmalardan yoqib/o‘chirish mumkin. "
            "U faylni yuklab olmaydi va zararli ekanini tasdiqlamaydi.")
    else:
        await send_text(session, chat_id, "🛡 Kerakli bo‘limni pastdagi menyudan tanlang.")


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
    elif text == BUTTON_OUTGOING_WARNING:
        await send_outgoing_warning_menu(session, store, chat_id)
    elif text in {BUTTON_UNKNOWN_SENDER, "👤 Yangi akkaunt ogohlantirishi"}:
        await send_unknown_sender_menu(session, store, chat_id)
    elif text == BUTTON_PHOTO_TEST:
        await send_photo_test_menu(session, chat_id)
    else:
        return False
    return True


def is_manual_scan_input(message: dict[str, Any]) -> bool:
    if message.get("document") or urls_from_message(message):
        return True
    body = f"{message.get('text') or ''} {message.get('caption') or ''}".lower()
    return any(phrase in body for phrase in SUSPICIOUS_PHRASES)


async def handle_manual_scan(session: aiohttp.ClientSession, message: dict[str, Any]) -> None:
    if (message.get("chat") or {}).get("type") != "private":
        return
    if not is_manual_scan_input(message):
        await send_text(session, int(message["chat"]["id"]), "🛡 Kerakli bo‘limni pastdagi menyudan tanlang.")
        return
    result = analyze(message)
    chat_id = int(message["chat"]["id"])
    if result:
        await send_text(session, chat_id, "🔎 <b>Xabarni tekshirish natijasi</b>")
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
        if isinstance(exc, TelegramTemporaryError):
            raise
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
        if isinstance(exc, TelegramTemporaryError):
            raise
        log.warning("Guruhga moderatsiya xabarini yubora olmadim (chat=%s): %s", chat_id, exc)


async def warn_recipient_about_suspicious_outgoing(
    session: aiohttp.ClientSession, owner_chat_id: int, message: dict[str, Any], connection_id: str,
    result: dict[str, Any],
) -> None:
    """Reply under a risky message sent from the connected business account."""
    chat_id = (message.get("chat") or {}).get("id")
    message_id = message.get("message_id")
    if not chat_id or not message_id:
        return

    text = (
        "⚠️ <b>Ogohlantirish:</b> Bu APK yoki havolani ochmang. "
        "Men yubormagan bo‘lishim mumkin — akkauntimga begona kirgan bo‘lishi ehtimol."
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
        if isinstance(exc, TelegramTemporaryError):
            raise
        log.warning("Shubhali Business xabar ostiga ogohlantirish yuborilmadi: %s", exc)
        try:
            await send_text(
                session,
                owner_chat_id,
                "⚠️ Telegram bu chatda ogohlantirishni yuborishga ruxsat bermadi. "
                "Telegram Business sozlamalarida <b>Javob berish</b> huquqini tekshiring; ayrim chatlarda bu funksiya cheklangan.",
            )
        except TelegramAPIError as notify_exc:
            if isinstance(notify_exc, TelegramTemporaryError):
                raise
            log.warning("Ogohlantirish yuborilmagani haqida egaga xabar berilmadi: %s", notify_exc)


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
        if isinstance(exc, TelegramTemporaryError):
            raise
        log.warning("Business xabarini o‘chira olmadim: %s", exc)
        try:
            await send_text(
                session,
                owner_chat_id,
                "⚠️ APK/dastur fayli yoki havola aniqlandi, lekin Telegram xabarni o‘chirishga ruxsat bermadi. "
                "Telegram Business → Chatbots → Qalqon AI bo‘limida "
                "<b>barcha xabarlarni o‘chirish</b> huquqini yoqing.",
            )
        except TelegramAPIError as notify_exc:
            if isinstance(notify_exc, TelegramTemporaryError):
                raise
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
            "🗑 <b>Xabar o‘chirildi.</b>\n\n"
            f"Yuboruvchi: {sender_label}\nAniqlangan: {html.escape(reason)}\n\n"
            "APK yoki havolani bot ochmadi va faylni yuklab olmadi.",
        )
    except TelegramAPIError as exc:
        if isinstance(exc, TelegramTemporaryError):
            raise
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
            if not await open_photo_test_invite(session, store, message):
                await handle_command(session, message)
        else:
            handled = await handle_keyboard_button(session, store, message)
            if not handled:
                await handle_manual_scan(session, message)
        return

    if "business_connection" in update:
        connection_id = update["business_connection"]["id"]
        info = await api(session, "getBusinessConnection", {"business_connection_id": connection_id})
        if not isinstance(info, dict) or info.get("id") != connection_id:
            raise TelegramAPIError("Business ulanishini tasdiqlab bo‘lmadi")
        store.save_connection(info)
        log.info("Business ulanish holati yangilandi")
        return

    if "callback_query" in update:
        query = update["callback_query"]
        data = query.get("data", "")
        if data.startswith("photo_test:"):
            await handle_photo_test_callback(session, store, query)
            return
        if data.startswith("trust_sender:"):
            await api(session, "answerCallbackQuery", {
                "callback_query_id": query["id"],
                "text": "Yangi yuboruvchi ogohlantirishi olib tashlangan.",
            })
            return
        toggle_setting = None
        if data in {"delete_mode:on", "delete_mode:off"}:
            toggle_setting = "delete_mode"
        elif data in {"outgoing_warning:on", "outgoing_warning:off"}:
            toggle_setting = "outgoing_warning"
        elif data in {"unknown_sender:on", "unknown_sender:off"}:
            toggle_setting = "unknown_sender"
        if toggle_setting:
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
            if toggle_setting == "outgoing_warning":
                enabled = data == "outgoing_warning:on"
                store.set_outgoing_warning(callback_user_id, enabled)
                text, keyboard = outgoing_warning_content(store, callback_user_id)
            elif toggle_setting == "unknown_sender":
                enabled = data == "unknown_sender:on"
                store.set_unknown_sender_warning(callback_user_id, enabled)
                text, keyboard = unknown_sender_content(store, callback_user_id)
            else:
                if enabled:
                    allowed, permission_text = await check_delete_permission(session, store, callback_user_id)
                    if not allowed:
                        await api(session, "answerCallbackQuery", {
                            "callback_query_id": query["id"],
                            "text": "O‘chirish ruxsati yo‘q yoki ulanish tekshirilmadi. Bot yuborgan ko‘rsatmani o‘qing.",
                            "show_alert": True,
                        })
                        await send_text(session, callback_chat_id, permission_text)
                        return
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
                if isinstance(exc, TelegramTemporaryError):
                    raise
                log.warning("Himoya sozlamasi xabarini yangilay olmadim: %s", exc)
            await send_text(
                session, callback_chat_id,
                "✅ Sozlama yoqildi." if enabled else "⏸ Sozlama o‘chirildi.",
            )
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
            if isinstance(exc, TelegramTemporaryError):
                raise
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

    await try_consented_photo_test(session, store, message, owner_chat_id, owner_user_id)

    # Only visible international numbers trigger this optional alert.
    if (
        sender_id and sender_id != owner_user_id
        and store.unknown_sender_warning_enabled(owner_user_id)
        and has_foreign_international_number(message)
    ):
        store.observe_sender(owner_user_id, int(sender_id))
        if store.mark_foreign_number_alerted(owner_user_id, int(sender_id)):
            await api(session, "sendMessage", {
                "chat_id": owner_chat_id,
                "text": foreign_number_alert(message),
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            })

    result = analyze(message)
    if not result:
        return
    if sender_id == owner_user_id:
        warning_reason = business_outgoing_warning_reason(message, result)
        if store.outgoing_warning_enabled(owner_user_id) and warning_reason:
            await warn_recipient_about_suspicious_outgoing(
                session, owner_chat_id, message, str(connection_id), result
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


def validate_update(update: Any) -> None:
    """Validate the consumed Telegram fields before any API call or state mutation."""
    def integer(value: Any, positive: bool = False) -> bool:
        return type(value) is int and abs(value) < 2**63 and (value > 0 if positive else value != 0)

    def obj(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("Invalid object")
        return value

    def string(value: Any, limit: int) -> None:
        if not isinstance(value, str) or len(value) > limit:
            raise ValueError("Invalid string")

    def user(value: Any) -> None:
        value = obj(value)
        if not integer(value.get("id"), True):
            raise ValueError("Invalid user")
        for name in ("first_name", "last_name", "username"):
            if name in value:
                string(value[name], 1024)

    update = obj(update)
    if type(update.get("update_id")) is not int or not 0 <= update["update_id"] < 2**63:
        raise ValueError("Invalid update id")
    # Bound nested structures even for optional fields we do not consume.
    pending = [(update, 0)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > 20000 or depth > 24:
            raise ValueError("Update too complex")
        if isinstance(value, dict):
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            if len(value) > 1024:
                raise ValueError("List too large")
            pending.extend((child, depth + 1) for child in value)
    kinds = [key for key in ALLOWED_UPDATES if key in update]
    if len(kinds) > 1:
        raise ValueError("Multiple update kinds")
    if not kinds:
        return  # Acknowledge unused Telegram update kinds without acting on them.
    kind = kinds[0]
    value = obj(update[kind])
    if kind == "business_connection":
        string(value.get("id"), 256)
        return  # Routing and ownership are fetched from Telegram, not this payload.
    if kind == "callback_query":
        string(value.get("id"), 256)
        user(value.get("from"))
        if "data" in value:
            string(value["data"], 64)
        if "message" not in value:
            return
        value = obj(value["message"])
    chat = obj(value.get("chat"))
    if not integer(chat.get("id")) or chat.get("type") not in {"private", "group", "supergroup", "channel"}:
        raise ValueError("Invalid chat")
    if not integer(value.get("message_id"), True):
        raise ValueError("Invalid message")
    if "from" in value:
        user(value["from"])
    if kind in {"business_message", "edited_business_message"}:
        string(value.get("business_connection_id"), 256)
        user(value.get("from"))
    for key in ("text", "caption"):
        if key in value:
            string(value[key], 65536)
    for key in ("entities", "caption_entities"):
        if key not in value:
            continue
        if not isinstance(value[key], list):
            raise ValueError("Invalid entities")
        for entity in value[key]:
            entity = obj(entity)
            string(entity.get("type"), 64)
            for field in ("offset", "length"):
                if type(entity.get(field)) is not int or not 0 <= entity[field] <= 131072:
                    raise ValueError("Invalid entity span")
            if "url" in entity:
                string(entity["url"], 8192)
    for key in ("document", "contact", "sender_chat", "sender_business_bot"):
        if key in value:
            obj(value[key])
    if "photo" in value:
        if not isinstance(value["photo"], list):
            raise ValueError("Invalid photos")
        for photo in value["photo"]:
            photo = obj(photo)
            if "file_id" in photo:
                string(photo["file_id"], 1024)
    for key, fields in (("document", ("file_name", "mime_type")), ("contact", ("phone_number",))):
        for field in fields:
            if field in value.get(key, {}):
                string(value[key][field], 1024)


async def process_authenticated_update(
    session: aiohttp.ClientSession, store: Store, update: dict[str, Any],
) -> None:
    validate_update(update)
    update_id = update["update_id"]
    if store.update_processed(update_id):
        return
    message = update.get("message") or update.get("edited_message")
    if message and message["chat"]["type"] == "private":
        actor = (message.get("from") or {}).get("id")
        if actor != message["chat"]["id"]:
            store.mark_update_processed(update_id)
            return
        if not PRIVATE_LIMITER.allow(("private", actor)):
            store.mark_update_processed(update_id)
            return
    query = update.get("callback_query")
    if query:
        actor = query["from"]["id"]
        callback_chat = (query.get("message") or {}).get("chat") or {}
        if callback_chat.get("type") != "private" or callback_chat.get("id") != actor:
            await api(session, "answerCallbackQuery", {"callback_query_id": query["id"]})
            store.mark_update_processed(update_id)
            return
        if not PRIVATE_LIMITER.allow(("callback", actor)):
            store.mark_update_processed(update_id)
            return
    await process_update(session, store, update)
    store.mark_update_processed(update_id)


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
                    await process_authenticated_update(session, store, update)
                except TelegramTemporaryError:
                    raise
                except (TelegramAPIError, KeyError, TypeError, ValueError) as exc:
                    log.warning("Yangilanishni qayta ishlashda xato: %s", exc)
                offset = int(update["update_id"]) + 1
                store.set_offset(offset)
        except asyncio.CancelledError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError, TelegramAPIError) as exc:
            log.warning("Telegram bilan aloqa uzildi; qayta uriniladi: %s", exc)
            await asyncio.sleep(3)


def create_webhook_app(
    session: aiohttp.ClientSession, store: Store, secret: str,
) -> web.Application:
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", secret):
        raise ValueError("WEBHOOK_SECRET kamida 32 belgili tasodifiy maxfiy kalit bo‘lishi kerak")
    secret_bytes = secret.encode("ascii")
    processing_lock = asyncio.Lock()
    pending = 0

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError("Invalid JSON constant")

    async def health(_: web.Request) -> web.Response:
        return web.json_response({"ok": True})

    async def webhook(request: web.Request) -> web.Response:
        nonlocal pending
        headers = request.headers.getall("X-Telegram-Bot-Api-Secret-Token", [])
        supplied = headers[0] if len(headers) == 1 else ""
        if len(supplied) > 256 or not secrets.compare_digest(supplied.encode("utf-8"), secret_bytes):
            raise web.HTTPForbidden()
        if request.content_type != "application/json":
            raise web.HTTPUnsupportedMediaType()
        if request.headers.get("Content-Encoding", "identity").lower() != "identity":
            raise web.HTTPUnsupportedMediaType()
        if request.content_length is not None and request.content_length > MAX_WEBHOOK_BYTES:
            raise web.HTTPRequestEntityTooLarge(max_size=MAX_WEBHOOK_BYTES, actual_size=request.content_length)
        if pending >= MAX_PENDING_UPDATES:
            raise web.HTTPServiceUnavailable(headers={"Retry-After": "5"})
        pending += 1
        acquired = False
        try:
            try:
                raw = await asyncio.wait_for(request.read(), timeout=10)
                update = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
                validate_update(update)
            except (ValueError, TypeError, RecursionError, UnicodeError):
                raise web.HTTPBadRequest(text="Invalid update") from None
            await asyncio.wait_for(processing_lock.acquire(), timeout=55)
            acquired = True
            await process_authenticated_update(session, store, update)
        except asyncio.TimeoutError:
            raise web.HTTPServiceUnavailable(headers={"Retry-After": "5"}) from None
        except (TelegramAPIError, KeyError, TypeError, ValueError, aiohttp.ClientError) as exc:
            log.warning("Webhook processing failed (%s)", type(exc).__name__)
            raise web.HTTPServiceUnavailable(text="Processing unavailable", headers={"Retry-After": "5"}) from None
        finally:
            if acquired:
                processing_lock.release()
            pending -= 1
        return web.json_response({"ok": True})

    async def secure_response(request: web.Request, response: web.StreamResponse) -> None:
        response.headers.pop("Server", None)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Strict-Transport-Security"] = "max-age=31536000"

    app = web.Application(client_max_size=MAX_WEBHOOK_BYTES)
    app.on_response_prepare.append(secure_response)
    app.router.add_get("/", health)
    app.router.add_get("/healthz", health)
    app.router.add_post(WEBHOOK_PATH, webhook)
    return app


async def run_webhook(session: aiohttp.ClientSession, store: Store) -> None:
    external_url = os.environ.get("RENDER_EXTERNAL_URL", "").rstrip("/")
    secret = os.environ.get("WEBHOOK_SECRET", "").strip()
    parsed = urlsplit(external_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path:
        raise SystemExit("Webhook uchun RENDER_EXTERNAL_URL to‘g‘ri HTTPS manzil bo‘lishi kerak")
    app = create_webhook_app(session, store, secret)
    runner = web.AppRunner(
        app, access_log=None, auto_decompress=False, keepalive_timeout=15,
        max_line_size=8190, max_field_size=8190, max_headers=64,
    )
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", int(os.environ.get("PORT", "10000")))
    await site.start()
    await api(session, "setWebhook", {
        "url": f"{external_url}{WEBHOOK_PATH}",
        "secret_token": secret,
        "max_connections": 4,
        "allowed_updates": ALLOWED_UPDATES,
        "drop_pending_updates": False,
    })
    log.info("Webhook ishga tushdi: %s%s", external_url, WEBHOOK_PATH)
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


async def run() -> None:
    if not re.fullmatch(r"[0-9]{6,}:[A-Za-z0-9_-]{20,}", BOT_TOKEN):
        raise SystemExit("BOT_TOKEN topilmadi yoki formati noto‘g‘ri. Render maxfiy sozlamasini tekshiring.")
    store = Store(DB_PATH)
    timeout = aiohttp.ClientTimeout(total=40, connect=15)
    connector = aiohttp.TCPConnector(limit=10, ttl_dns_cache=300)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        me = await api(session, "getMe")
        log.info("Bot ishga tushdi: @%s", me.get("username", "unknown"))
        try:
            await api(session, "deleteMyCommands")
        except TelegramAPIError as exc:
            if isinstance(exc, TelegramTemporaryError):
                raise
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
