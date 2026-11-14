"""Telegram Business security assistant.

Monitors only business chats explicitly granted to the bot. Automatic monitoring
does not download files. Owner-requested APK inspection uses bounded memory or a
temporary upload file with explicit consent. Opt-in history stores text and media identifiers.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from urllib.parse import parse_qsl
from collections import Counter, OrderedDict, deque
import html
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
from threat_intel import DomainReputation, HashReputation, MAX_APK_BYTES, MAX_UPLOAD_BYTES, RISK_PERMISSIONS, inspect_apk, inspect_apk_file
from apk_upload import ApkUploadService
from subscription import SubscriptionGate


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
THREAT_INTEL = DomainReputation(DATA_DIR / "phishing_domains.txt")
HASH_REPUTATION = HashReputation(os.environ.get("VIRUSTOTAL_API_KEY", ""))
APK_UPLOAD_SERVICE = ApkUploadService(os.environ.get("RENDER_EXTERNAL_URL", ""))
SUBSCRIPTION_GATE = SubscriptionGate(os.environ.get("REQUIRED_CHANNEL", "@qalqon_ai1").strip())
REQUIRED_CHANNEL_URL = os.environ.get("REQUIRED_CHANNEL_URL", "https://t.me/qalqon_ai1").strip()
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
BUTTON_HISTORY = "📝 O‘chirilgan xabarlar"
BUTTON_SECURITY_CENTER = "🛡 Xavfsizlik markazi"
BUTTON_APK_UPLOAD = "🔬 APK tekshirish · 100 MB"
MAIN_KEYBOARD = {
    "keyboard": [
        [BUTTON_STATUS, BUTTON_TIPS],
        [BUTTON_SCAN, BUTTON_HELP],
        [BUTTON_APK_UPLOAD],
        [BUTTON_DELETE_MODE],
        [BUTTON_OUTGOING_WARNING],
        [BUTTON_HISTORY],
        [BUTTON_SECURITY_CENTER],
    ],
    "resize_keyboard": True,
    "is_persistent": True,
    "one_time_keyboard": False,
    "selective": False,
    "input_field_placeholder": "Tugmalardan birini tanlang",
}
ALLOWED_UPDATES = [
    "message", "business_connection", "business_message",
    "edited_business_message", "edited_message", "callback_query", "deleted_business_messages",
]

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("telegram_himoya")


def redact_secrets(text: str) -> str:
    for value in (BOT_TOKEN, os.environ.get("WEBHOOK_SECRET", ""), os.environ.get("VIRUSTOTAL_API_KEY", "")):
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
SUBSCRIPTION_NOTICE_LIMITER = InteractionLimiter(capacity=1, period=600)
APK_SCAN_LIMITER = InteractionLimiter(capacity=3, period=3600)
APK_REQUESTS: OrderedDict[str, dict[str, Any]] = OrderedDict()
APK_SCAN_JOBS: set[asyncio.Task] = set()
APK_SCAN_SEMAPHORE = asyncio.Semaphore(1)


MEDIA_METHODS = {
    "photo": "sendPhoto", "video": "sendVideo", "voice": "sendVoice",
    "audio": "sendAudio", "document": "sendDocument", "animation": "sendAnimation",
    "video_note": "sendVideoNote", "sticker": "sendSticker",
}


def history_media(message: dict[str, Any]) -> dict[str, str] | None:
    # Do not retain protected, paid or disappearing media. No file download/bypass.
    if any(message.get(k) for k in ("has_protected_content", "paid_media", "ttl_seconds", "self_destruct_time")):
        return None
    for kind in ("animation", "photo", "video", "voice", "audio", "document", "video_note", "sticker"):
        value = message.get(kind)
        if kind == "photo" and isinstance(value, list):
            value = value[-1] if value else None
        if not isinstance(value, dict) or value.get("ttl_seconds"):
            continue
        file_id = value.get("file_id")
        if isinstance(file_id, str) and 0 < len(file_id) <= 512:
            return {"kind": kind, "file_id": file_id}
    return None


class TemporaryMessageHistory:
    """Opt-in bounded snapshots. PostgreSQL backend is configured separately."""

    def __init__(self, ttl: float = 259200, per_owner: int = 1000, total: int = 20000) -> None:
        self.ttl, self.per_owner, self.total = ttl, per_owner, total
        self.items: OrderedDict[tuple[str, int, int], dict[str, Any]] = OrderedDict()

    def prune(self) -> None:
        now = time.monotonic()
        for key in [key for key, item in self.items.items() if item["expires"] <= now]:
            del self.items[key]

    def clear(self, owner: int) -> None:
        for key in [key for key, item in self.items.items() if item["owner"] == owner]:
            del self.items[key]

    def remember(self, owner: int, connection: str, message: dict[str, Any], ignored: bool = False) -> None:
        self.prune()
        key = (connection, int(message["chat"]["id"]), int(message["message_id"]))
        previous = self.items.pop(key, None)
        sender = message.get("from") or {}
        name = " ".join(str(sender.get(field) or "") for field in ("first_name", "last_name")).strip()
        name = ("@" + sender["username"]) if sender.get("username") else name or str(sender.get("id") or "Noma’lum")
        media = history_media(message) if not ignored else None
        text = message.get("text") or message.get("caption") or ("[" + media["kind"] + "]" if media else "[Bu turdagi xabar saqlanmaydi]")
        self.items[key] = {
            "owner": owner, "sender": name[:128], "text": "" if ignored else str(text)[:4096],
            "expires": time.monotonic() + self.ttl, "deleted": previous["deleted"] if previous else False, "ignored": ignored, "media": media,
            "token": previous["token"] if previous else secrets.token_urlsafe(12),
        }
        owner_keys = [key for key, item in self.items.items() if item["owner"] == owner]
        for key in owner_keys[:-self.per_owner]:
            del self.items[key]
        while len(self.items) > self.total:
            self.items.popitem(last=False)

    def mark_deleted(self, owner: int, connection: str, chat_id: int, message_ids: list[int]) -> tuple[int, int]:
        self.prune()
        found = missing = 0
        for message_id in set(message_ids):
            item = self.items.get((connection, chat_id, message_id))
            if item is None or item["owner"] != owner:
                missing += 1
            elif not item["ignored"] and not item["deleted"]:
                item["deleted"] = True
                item["expires"] = time.monotonic() + self.ttl
                found += 1
        return found, missing

    def deleted(self, owner: int) -> list[dict[str, Any]]:
        self.prune()
        return [dict(item, chat_id=key[1], connection=key[0])
                for key, item in reversed(self.items.items())
                if item["owner"] == owner and item["deleted"]]

    def detail(self, owner: int, token: str) -> dict[str, Any] | None:
        return next((item for item in self.deleted(owner) if item["token"] == token), None)


class PostgresMessageHistory:
    """Durable, owner-scoped 72-hour history; all SQL values are bound parameters."""

    def __init__(self, url: str) -> None:
        import psycopg
        self.driver, self.url = psycopg, url
        self._execute([
            ("CREATE TABLE IF NOT EXISTS qalqon_history (connection TEXT NOT NULL, chat BIGINT NOT NULL, message BIGINT NOT NULL, owner BIGINT NOT NULL, expires DOUBLE PRECISION NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(connection,chat,message))", ()),
            ("CREATE INDEX IF NOT EXISTS qalqon_history_owner_age ON qalqon_history(owner,expires)", ()),
            ("CREATE TABLE IF NOT EXISTS qalqon_history_settings (owner BIGINT PRIMARY KEY, enabled INTEGER NOT NULL)", ()),
            ("CREATE TABLE IF NOT EXISTS qalqon_security_events (id BIGSERIAL PRIMARY KEY, owner BIGINT NOT NULL, connection TEXT NOT NULL, chat BIGINT NOT NULL, chat_label TEXT NOT NULL, category TEXT NOT NULL, action TEXT NOT NULL, score INTEGER NOT NULL, created_at DOUBLE PRECISION NOT NULL)", ()),
            ("CREATE INDEX IF NOT EXISTS qalqon_security_events_owner_age ON qalqon_security_events(owner,created_at)", ()),
        ])
        self.prune()

    def _execute(self, statements):
        try:
            with self.driver.connect(self.url, connect_timeout=30, sslmode="require") as connection:
                result = []
                for sql, values in statements:
                    cursor = connection.execute(sql, values)
                    result = cursor.fetchall() if cursor.description else []
                return result
        except self.driver.Error as exc:
            detail = str(exc).lower()
            reason = "database_error"
            for marker, category in (
                ("invalid connection option", "invalid_connection_string"),
                ("missing", "invalid_connection_string"),
                ("password authentication failed", "authentication_failed"),
                ("could not translate host", "hostname_resolution_failed"),
                ("name or service not known", "hostname_resolution_failed"),
                ("timeout", "connection_timeout"),
                ("unsupported startup parameter", "unsupported_startup_parameter"),
                ("permission denied", "database_permission_denied"),
                ("syntax error", "sql_syntax_error"),
                ("ssl", "tls_connection_error"),
            ):
                if marker in detail:
                    reason = category
                    break
            state = getattr(exc, "sqlstate", None)
            state = state if isinstance(state, str) and re.fullmatch(r"[A-Z0-9]{5}", state) else "none"
            log.error("History database failure: category=%s sqlstate=%s", reason, state)
            # Never leak credentials, SQL parameters or message bodies to logs.
            raise TelegramTemporaryError("Tarix bazasi vaqtincha mavjud emas") from None

    def prune(self):
        now = time.time()
        self._execute([
            ("DELETE FROM qalqon_history WHERE expires<=%s", (now,)),
            ("DELETE FROM qalqon_security_events WHERE created_at<%s", (now - 30 * 86400,)),
        ])

    def clear(self, owner):
        self._execute([("DELETE FROM qalqon_history WHERE owner=%s", (owner,))])

    def enabled(self, owner):
        rows = self._execute([("SELECT enabled FROM qalqon_history_settings WHERE owner=%s", (owner,))])
        return bool(rows and rows[0][0])

    def set_enabled(self, owner, enabled):
        self._execute([("INSERT INTO qalqon_history_settings(owner,enabled) VALUES(%s,%s) ON CONFLICT(owner) DO UPDATE SET enabled=excluded.enabled", (owner, int(enabled)))])

    def remember(self, owner, connection, message, ignored=False):
        key = (connection, int(message["chat"]["id"]), int(message["message_id"]))
        old = self._execute([("SELECT payload FROM qalqon_history WHERE connection=%s AND chat=%s AND message=%s AND owner=%s AND expires>%s", (*key, owner, time.time()))])
        temporary = TemporaryMessageHistory()
        temporary.remember(owner, connection, message, ignored)
        item = temporary.items[key]
        if old:
            previous = json.loads(old[0][0])
            item.update(token=previous["token"], deleted=previous["deleted"])
        item["expires"] = time.time() + 259200
        self._execute([
            ("INSERT INTO qalqon_history(connection,chat,message,owner,expires,payload) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(connection,chat,message) DO UPDATE SET owner=excluded.owner,expires=excluded.expires,payload=excluded.payload", (*key, owner, item["expires"], json.dumps(item))),
            ("DELETE FROM qalqon_history WHERE expires<=%s", (time.time(),)),
            ("DELETE FROM qalqon_history WHERE owner=%s AND (connection,chat,message) IN (SELECT connection,chat,message FROM qalqon_history WHERE owner=%s ORDER BY expires DESC OFFSET 1000)", (owner, owner)),
            ("DELETE FROM qalqon_history WHERE (connection,chat,message) IN (SELECT connection,chat,message FROM qalqon_history ORDER BY expires DESC OFFSET 20000)", ()),
        ])

    def mark_deleted(self, owner, connection, chat_id, message_ids):
        rows = self._execute([("SELECT message,payload FROM qalqon_history WHERE owner=%s AND connection=%s AND chat=%s AND expires>%s", (owner, connection, chat_id, time.time()))])
        records = {row[0]: json.loads(row[1]) for row in rows}
        found = missing = 0
        writes = []
        for message_id in set(message_ids):
            item = records.get(message_id)
            if item is None:
                missing += 1
            elif not item["ignored"] and not item["deleted"]:
                item["deleted"] = True
                item["expires"] = time.time() + 259200
                found += 1
                writes.append(("UPDATE qalqon_history SET payload=%s,expires=%s WHERE owner=%s AND connection=%s AND chat=%s AND message=%s", (json.dumps(item), item["expires"], owner, connection, chat_id, message_id)))
        if writes:
            self._execute(writes)
        return found, missing

    def deleted(self, owner):
        rows = self._execute([("SELECT chat,connection,payload FROM qalqon_history WHERE owner=%s AND expires>%s ORDER BY expires DESC", (owner, time.time()))])
        return [dict(item, chat_id=row[0], connection=row[1])
                for row in rows if (item := json.loads(row[2]))["deleted"]]

    def detail(self, owner, token):
        return next((item for item in self.deleted(owner) if item["token"] == token), None)

    def record_security_event(self, owner, connection, chat_id, chat_label, category, action, score):
        now = time.time()
        self._execute([
            ("INSERT INTO qalqon_security_events(owner,connection,chat,chat_label,category,action,score,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
             (owner, connection, chat_id, chat_label, category, action, score, now)),
            ("DELETE FROM qalqon_security_events WHERE created_at<%s", (now - 30 * 86400,)),
            ("DELETE FROM qalqon_security_events WHERE owner=%s AND id IN (SELECT id FROM qalqon_security_events WHERE owner=%s ORDER BY created_at DESC OFFSET 1000)", (owner, owner)),
        ])

    def security_events(self, owner, since):
        return self._execute([
            ("DELETE FROM qalqon_security_events WHERE created_at<%s", (time.time() - 30 * 86400,)),
            ("SELECT chat,chat_label,category,action,score,created_at FROM qalqon_security_events WHERE owner=%s AND created_at>=%s ORDER BY created_at DESC LIMIT 1000", (owner, since)),
        ])


DELETED_HISTORY = TemporaryMessageHistory()
DELETION_NOTICE_LIMITER = InteractionLimiter(capacity=6)

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
        self.db.execute("DROP TABLE IF EXISTS photo_tests")
        self.db.execute("DROP TABLE IF EXISTS sender_profiles")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS processed_updates ("
            "update_id INTEGER PRIMARY KEY, processed_at INTEGER NOT NULL)"
        )
        self.db.execute("CREATE INDEX IF NOT EXISTS processed_updates_age ON processed_updates(processed_at)")
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
            "outgoing_warning INTEGER NOT NULL DEFAULT 0)"
        )
        setting_columns = {row[1] for row in self.db.execute("PRAGMA table_info(user_settings)")}
        if "outgoing_warning" not in setting_columns:
            self.db.execute(
                "ALTER TABLE user_settings ADD COLUMN outgoing_warning INTEGER NOT NULL DEFAULT 0"
            )
        if "deleted_history" not in setting_columns:
            self.db.execute("ALTER TABLE user_settings ADD COLUMN deleted_history INTEGER NOT NULL DEFAULT 0")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS qalqon_security_events ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, owner_user_id INTEGER NOT NULL, "
            "connection_id TEXT NOT NULL, chat_id INTEGER NOT NULL, chat_label TEXT NOT NULL, "
            "category TEXT NOT NULL, action TEXT NOT NULL, score INTEGER NOT NULL, created_at REAL NOT NULL)"
        )
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS qalqon_security_events_owner_age "
            "ON qalqon_security_events(owner_user_id,created_at)"
        )
        self.db.execute("DELETE FROM qalqon_security_events WHERE created_at<?", (time.time() - 30 * 86400,))
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


    def set_offset(self, offset: int) -> None:
        self.db.execute(
            "INSERT INTO state(key,value) VALUES('update_offset',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(offset),)
        )
        self.db.commit()

    def history_enabled(self, owner: int) -> bool:
        if isinstance(DELETED_HISTORY, PostgresMessageHistory):
            return DELETED_HISTORY.enabled(owner)
        row = self.db.execute("SELECT deleted_history FROM user_settings WHERE owner_user_id=?", (owner,)).fetchone()
        return bool(row[0]) if row else False

    def set_history(self, owner: int, enabled: bool) -> None:
        if isinstance(DELETED_HISTORY, PostgresMessageHistory):
            DELETED_HISTORY.set_enabled(owner, enabled)
        self.db.execute(
            "INSERT INTO user_settings(owner_user_id,deleted_history) VALUES(?,?) "
            "ON CONFLICT(owner_user_id) DO UPDATE SET deleted_history=excluded.deleted_history",
            (owner, int(enabled)),
        )
        self.db.commit()

    def record_security_event(
        self, owner: int, connection: str, chat_id: int, chat_label: str,
        category: str, action: str, score: int,
    ) -> None:
        if isinstance(DELETED_HISTORY, PostgresMessageHistory):
            try:
                DELETED_HISTORY.record_security_event(
                    owner, connection, chat_id, chat_label, category, action, score,
                )
            except TelegramTemporaryError:
                # The protection action must not fail because an optional report entry could not be saved.
                log.warning("Xavfsizlik hisobotiga hodisani yozib bo‘lmadi")
            return
        now = time.time()
        self.db.execute(
            "INSERT INTO qalqon_security_events(owner_user_id,connection_id,chat_id,chat_label,category,action,score,created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (owner, connection, chat_id, chat_label[:96], category[:32], action[:32], max(0, min(100, score)), now),
        )
        self.db.execute("DELETE FROM qalqon_security_events WHERE created_at<?", (now - 30 * 86400,))
        self.db.execute(
            "DELETE FROM qalqon_security_events WHERE owner_user_id=? AND id IN "
            "(SELECT id FROM qalqon_security_events WHERE owner_user_id=? ORDER BY created_at DESC LIMIT -1 OFFSET 1000)",
            (owner, owner),
        )
        self.db.commit()

    def security_events(self, owner: int, since: float) -> list[tuple[Any, ...]]:
        if isinstance(DELETED_HISTORY, PostgresMessageHistory):
            return DELETED_HISTORY.security_events(owner, since)
        self.db.execute("DELETE FROM qalqon_security_events WHERE created_at<?", (time.time() - 30 * 86400,))
        self.db.commit()
        return self.db.execute(
            "SELECT chat_id,chat_label,category,action,score,created_at FROM qalqon_security_events "
            "WHERE owner_user_id=? AND created_at>=? ORDER BY created_at DESC LIMIT 1000",
            (owner, since),
        ).fetchall()


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
    if THREAT_INTEL.matches(host):
        score = max(score, 90)
        reasons.insert(0, "Phishing.Database bazasida ushbu domen fishing xavfi sifatida qayd etilgan")
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


def security_event_category(message: dict[str, Any], result: dict[str, Any]) -> str:
    document = message.get("document") or {}
    file_name = str(document.get("file_name") or result.get("file_name") or "").lower()
    mime = str(document.get("mime_type") or "").lower()
    if file_name.endswith(".apk") or mime == "application/vnd.android.package-archive":
        return "APK"
    if urls_from_message(message):
        return "Havola"
    return "Shubhali matn"


def security_chat_label(message: dict[str, Any]) -> str:
    chat = message.get("chat") or {}
    username = str(chat.get("username") or "").strip()
    if username:
        return "@" + username[:95]
    name = " ".join(str(chat.get(field) or "").strip() for field in ("first_name", "last_name")).strip()
    return name[:96] if name else f"Chat {chat.get('id', '')}"[:96]


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
    if result["links"]:
        lines.append("🛡 Domen bazasi: " + THREAT_INTEL.status())
    lines.append("\n<b>Sabab:</b>")
    lines.extend(f"• {html.escape(reason[:256])}" for reason in result["reasons"][:5])
    if not result["reasons"]:
        lines.append("• Havola bor. Hozir ishlayotgan tekshiruvlarda boshqa xavf belgisi topilmadi; bu xavfsizlik kafolati emas.")
    lines.append("\nNoma’lum APK’ni o‘rnatmang, havolada Telegram kodi yoki parolni kiritmang.")
    # Bound visible fields before escaping; slicing HTML can break tags/entities.
    return "\n".join(lines)


def alert_keyboard(result: dict[str, Any]) -> dict[str, Any]:
    category = "apk" if result["file_name"].lower().endswith(".apk") else "link"
    return {"inline_keyboard": [[
        {"text": "Nega ogohlantirdi?", "callback_data": f"why:{category}"},
        {"text": "Xavfsizlik maslahati", "callback_data": "tips"},
    ]]}


async def subscription_state(session: aiohttp.ClientSession, owner: int, force: bool = False) -> str:
    return await SUBSCRIPTION_GATE.check(lambda method, payload: api(session, method, payload), owner, force=force)


async def subscription_upload_allowed(session: aiohttp.ClientSession, owner: int) -> bool:
    return await subscription_state(session, owner, force=True) == "member"


async def send_subscription_prompt(session: aiohttp.ClientSession, owner: int, state: str) -> None:
    text = (
        "📢 <b>Botdan foydalanish uchun kanalimizga obuna bo‘ling.</b>\n\n"
        "1. «Obuna bo‘lish» tugmasini bosing.\n"
        "2. Kanalga a’zo bo‘ling.\n"
        "3. Shu yerga qaytib «Obunani tekshirish»ni bosing."
    )
    if state == "unavailable":
        text = "⚠️ <b>Obunani hozir tekshirib bo‘lmadi.</b>\n\nBot kanalga administrator qilib qo‘shilgan bo‘lishi kerak. Birozdan keyin «Obunani tekshirish»ni bosing."
    await api(session, "sendMessage", {
        "chat_id": owner, "text": text, "parse_mode": "HTML",
        "reply_markup": {"inline_keyboard": [
            [{"text": "📢 Obuna bo‘lish", "url": REQUIRED_CHANNEL_URL}],
            [{"text": "✅ Obunani tekshirish", "callback_data": "subscription:check"}],
        ]},
    })


async def business_subscription_allowed(session: aiohttp.ClientSession, owner: int, owner_chat: int) -> bool:
    state = await subscription_state(session, owner)
    if state == "member":
        return True
    if SUBSCRIPTION_NOTICE_LIMITER.allow(("subscription", owner)):
        await send_subscription_prompt(session, owner_chat, state)
    return False


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
            "• Guruhda APK, dastur fayli va havolalarni o‘chirib, guruhga xabar beradi.\n\n"
            "• <b>📝 O‘chirilgan xabarlar</b> — o‘zingiz yoqsangiz, kelgan xabar matnini vaqtincha eslab turib, o‘chirilganda ko‘rsatadi.\n\n"
            "• <b>🛡 Xavfsizlik markazi</b> — ulanish va rejim holati, so‘nggi 7 kun hisoboti hamda chatlar bo‘yicha hodisalarni ko‘rsatadi. Hisobot uchun xabar matni yoki to‘liq havola saqlanmaydi.\n\n"
            "<b>Qanday yoqiladi?</b>\n"
            "1. Telegram <b>Sozlamalar → Telegram Business → Chatbots</b>ga kiring, Qalqon AI’ni tanlang va kerakli chatlarga ruxsat bering.\n"
            "2. Pastdagi sozlamalardan kerakli rejimni yoqing. Avto o‘chirish uchun <b>barcha xabarlarni o‘chirish</b>, yuborilgan xabar ogohlantirishi uchun <b>Javob berish</b> huquqini bering.\n"
            "3. Guruh himoyasi uchun botni guruhga qo‘shib, administrator qiling va <b>Delete Messages</b> huquqini bering.\n\n"
            "🔬 <b>APK tekshirish · 100 MB</b> tugmasi orqali katta APK’ni tanlab, ruxsatlari va SHA-256 xeshini tekshirtiring. 20 MB gacha faylni botga bevosita yuborish ham mumkin. Havola domenlari Phishing.Database ro‘yxati bilan solishtiriladi.\n\n"
            "⚠️ Bot to‘liq antivirus emas. Avtomatik kuzatuv fayllarni yuklab olmaydi; chuqur APK tekshiruvi faqat roziligingiz bilan bajariladi. Tarix rejimi yoqilsa matn va media identifikatori 3 kungacha saqlanadi."
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


async def send_history_menu(session: aiohttp.ClientSession, store: Store, owner: int) -> None:
    status = "🟢 YOQILGAN" if store.history_enabled(owner) else "⚪ O‘CHIRILGAN"
    await send_text(session, owner,
        f"📝 <b>O‘chirilgan xabarlar: {status}</b>\n\n"
        "Yoqsangiz, bot yangi kiruvchi xabarlarning matni va oddiy media identifikatorini "
        "72 soatgacha (3 kun), oxirgi 1000 ta xabar doirasida saqlaydi. O‘chirilishi aniqlansa yana 3 kun saqlaydi. "
        "Rasm, video, ovoz, audio, hujjat, GIF va stiker qo‘llanadi. Fayl yuklab olinmaydi. "
        "Bir martalik va himoyalangan media saqlanmaydi.\n\n"
        + ("✅ Tashqi baza ulangan: tarix server restartidan keyin ham qoladi.\n\n" if isinstance(DELETED_HISTORY, PostgresMessageHistory) else
           "⚠️ Doimiy baza hali ulanmagan: restartda tarix yo‘qoladi, 3 kun kafolatlanmaydi.\n\n") +
        "Telegram o‘chirish hodisasini yuborsa, oldindan eslab qolingan matnni shu bot chatida ko‘rishingiz mumkin. "
        "Bot rejim yoqilishidan oldingi yoki botga kelmagan xabarlarni tiklamaydi. "
        "Butun chat o‘chirilganda hodisa kelishi kafolatlanmaydi; kim o‘chirganini API bildirmaydi.\n\n"
        "O‘chirsangiz, serverdagi vaqtinchalik nusxalar ham tozalanadi. Bot allaqachon sizga yuborgan "
        "matnlar Telegram bot chattingizda qoladi.")
    await api(session, "sendMessage", {
        "chat_id": owner, "text": "Xabarlarni vaqtincha eslab turishga rozimisiz?",
        "reply_markup": {"inline_keyboard": [[
            {"text": "✅ Roziman, yoqish", "callback_data": "history:on"},
            {"text": "⏸ O‘chirish", "callback_data": "history:off"},
        ], [{"text": "📖 O‘chirilganlarni ko‘rish", "callback_data": "history:list:0"}],
        [{"text": "🧹 Vaqtinchalik xotirani tozalash", "callback_data": "history:clear"}]]},
    })


async def send_deleted_list(session: aiohttp.ClientSession, owner: int, page: int = 0) -> None:
    records = DELETED_HISTORY.deleted(owner)
    page_size = 10
    page = max(0, min(page, max(0, (len(records) - 1) // page_size)))
    selected = records[page * page_size:page * page_size + page_size]
    if not selected:
        await send_text(session, owner, "Hozircha vaqtinchalik xotirada o‘chirilgan xabar yo‘q.")
        return
    lines = ["📝 <b>O‘chirilgan xabarlar</b>", f"{page * page_size + 1}–{page * page_size + len(selected)} / {len(records)}", ""]
    for index, item in enumerate(selected, page * page_size + 1):
        preview = item["text"][:110] or "[Matn yo‘q]"
        if item.get("media"):
            preview = "📎 " + item["media"]["kind"] + " · " + preview
        lines.append(f"<b>{index}. {html.escape(item['sender'])}</b> — {html.escape(preview)}")
    buttons = [[{"text": "📨 Shu 10 ta xabarni yuborish", "callback_data": f"history:batch:{page}"}],
               [{"text": "📨 Barcha o‘chirilganlarni yuborish", "callback_data": "history:all"}]]
    navigation = []
    if page:
        navigation.append({"text": "⬅️ Oldingi 10 ta", "callback_data": f"history:list:{page - 1}"})
    if (page + 1) * page_size < len(records):
        navigation.append({"text": "Keyingi 10 ta ➡️", "callback_data": f"history:list:{page + 1}"})
    if navigation:
        buttons.append(navigation)
    await api(session, "sendMessage", {
        "chat_id": owner, "text": "\n".join(lines), "parse_mode": "HTML",
        "disable_web_page_preview": True, "reply_markup": {"inline_keyboard": buttons},
    })


async def send_deleted_item(session: aiohttp.ClientSession, owner: int, item: dict[str, Any]) -> None:
    media = item.get("media")
    body = item.get("text") or "[Matn yo‘q]"
    heading = f"📝 <b>{html.escape(item['sender'])}</b>\n"
    try:
        if media:
            field = media["kind"]
            await api(session, MEDIA_METHODS[field], {
                "chat_id": owner, field: media["file_id"],
                "caption": (heading + html.escape(body))[:1000],
                "parse_mode": "HTML", "protect_content": True,
            })
        else:
            for offset in range(0, len(body), 3000):
                await api(session, "sendMessage", {
                    "chat_id": owner,
                    "text": heading + "<pre>" + html.escape(body[offset:offset + 3000]) + "</pre>",
                    "parse_mode": "HTML", "protect_content": True,
                    "disable_web_page_preview": True,
                })
    except TelegramAPIError as exc:
        if isinstance(exc, TelegramTemporaryError):
            raise
        await send_text(session, owner, "⚠️ Xabardagi mediani qayta yuborib bo‘lmadi; Telegram faylga ruxsat bermadi.")


async def send_deleted_chats(session: aiohttp.ClientSession, owner: int, page: int = 0) -> None:
    grouped: dict[int, list[dict[str, Any]]] = {}
    for item in DELETED_HISTORY.deleted(owner):
        grouped.setdefault(int(item["chat_id"]), []).append(item)
    chats = list(grouped.items())
    if not chats:
        await send_text(session, owner, "Hozircha tanlash uchun o‘chirilgan chat yo‘q.")
        return
    page_size = 10
    page = max(0, min(page, max(0, (len(chats) - 1) // page_size)))
    selected = chats[page * page_size:page * page_size + page_size]
    rows = []
    for chat_id, items in selected:
        latest = items[0]
        label = html.escape(latest["sender"][:30])
        rows.append([{"text": f"💬 {label} · {len(items)} ta xabar", "callback_data": f"history:chat:{chat_id}"}])
    nav = []
    if page:
        nav.append({"text": "⬅️ Oldingi", "callback_data": f"history:chats:{page - 1}"})
    if (page + 1) * page_size < len(chats):
        nav.append({"text": "Keyingi ➡️", "callback_data": f"history:chats:{page + 1}"})
    if nav:
        rows.append(nav)
    await api(session, "sendMessage", {
        "chat_id": owner, "text": "💬 <b>Qaysi chatdan o‘chirilgan xabarlarni ko‘rmoqchisiz?</b>",
        "parse_mode": "HTML", "reply_markup": {"inline_keyboard": rows},
    })


async def send_all_deleted(session: aiohttp.ClientSession, owner: int, chat_id: int | None = None) -> None:
    records = DELETED_HISTORY.deleted(owner)
    if chat_id is not None:
        records = [item for item in records if int(item["chat_id"]) == chat_id]
    if not records:
        await send_text(session, owner, "Hozircha ko‘rsatadigan o‘chirilgan xabar yo‘q.")
        return
    await send_text(session, owner, f"📨 {len(records)} ta o‘chirilgan xabar yuborilyapti…")
    text_parts: list[str] = []
    size = 0

    async def flush_text() -> None:
        nonlocal text_parts, size
        if text_parts:
            await api(session, "sendMessage", {
                "chat_id": owner, "text": "\n\n────────────\n\n".join(text_parts),
                "parse_mode": "HTML", "protect_content": True,
                "disable_web_page_preview": True,
            })
            text_parts, size = [], 0

    for index, item in enumerate(records, 1):
        media = item.get("media")
        if media:
            await flush_text()
            await send_deleted_item(session, owner, item)
            continue
        body = item.get("text") or "[Matn yo‘q]"
        part = f"<b>{index}. {html.escape(item['sender'])}</b>\n<pre>{html.escape(body)}</pre>"
        if size + len(part) > 3500:
            await flush_text()
        text_parts.append(part)
        size += len(part)
    await flush_text()


async def handle_history_callback(session: aiohttp.ClientSession, store: Store, query: dict[str, Any]) -> None:
    owner = int(query["from"]["id"])
    data = str(query.get("data") or "")
    await api(session, "answerCallbackQuery", {"callback_query_id": query["id"]})
    if data == "history:on":
        if not store.active_connection_id(owner):
            await send_text(session, owner, "Avval botni Telegram Business orqali shu akkauntingizga ulang.")
            return
        store.set_history(owner, True)
        await send_text(session, owner, "✅ Rejim yoqildi: matn va oddiy media 72 soatgacha, oxirgi 1000 ta xabar doirasida. Saqlash holati rejim menyusida ko‘rsatilgan.")
    elif data in {"history:off", "history:clear"}:
        if data == "history:off":
            store.set_history(owner, False)
        DELETED_HISTORY.clear(owner)
        await send_text(session, owner, "🧹 Serverdagi vaqtinchalik xotira tozalandi." + (" Rejim o‘chirildi." if data == "history:off" else ""))
    elif not store.history_enabled(owner):
        await send_text(session, owner, "Bu rejim o‘chiq. Pastdagi O‘chirilgan xabarlar bo‘limidan yoqing.")
    elif data.startswith("history:list:"):
        try:
            page = int(data.rsplit(":", 1)[1])
        except ValueError:
            page = 0
        await send_deleted_list(session, owner, page)
    elif data.startswith("history:chats:"):
        try:
            page = int(data.rsplit(":", 1)[1])
        except ValueError:
            page = 0
        await send_deleted_chats(session, owner, page)
    elif data.startswith("history:chat:"):
        try:
            chat_id = int(data.rsplit(":", 1)[1])
        except ValueError:
            chat_id = 0
        if not any(int(item["chat_id"]) == chat_id for item in DELETED_HISTORY.deleted(owner)):
            await send_text(session, owner, "Bu chatda ko‘rsatadigan o‘chirilgan xabar topilmadi.")
            return
        await send_all_deleted(session, owner, chat_id)
    elif data == "history:all":
        await send_deleted_chats(session, owner)
    elif data.startswith("history:batch:"):
        try:
            page = int(data.rsplit(":", 1)[1])
        except ValueError:
            page = 0
        if page < 0:
            page = 0
        records = DELETED_HISTORY.deleted(owner)
        for item in records[page * 10:page * 10 + 10]:
            await send_deleted_item(session, owner, item)
    elif data.startswith("history:view:"):
        item = DELETED_HISTORY.detail(owner, data[len("history:view:"):])
        if item is None:
            await send_text(session, owner, "Bu xabar xotirada yo‘q yoki saqlash muddati tugagan.")
            return
        await send_deleted_item(session, owner, item)


async def handle_business_deletions(session: aiohttp.ClientSession, store: Store, event: dict[str, Any]) -> None:
    connection_id = event["business_connection_id"]
    connection = store.connection(connection_id)
    if connection is None:
        info = await api(session, "getBusinessConnection", {"business_connection_id": connection_id})
        store.save_connection(info)
        connection = store.connection(connection_id)
    if not connection:
        return
    owner_chat, owner = connection
    if not await business_subscription_allowed(session, owner, owner_chat):
        return
    if not store.history_enabled(owner):
        return
    found, missing = DELETED_HISTORY.mark_deleted(owner, connection_id, event["chat"]["id"], event["message_ids"])
    if not (found or missing) or not DELETION_NOTICE_LIMITER.allow(("deletion", owner)):
        return
    text = f"🗑 Suhbatda xabarlar o‘chirildi.\n\nBot oldindan eslab qolgan: {found} ta."
    if missing:
        text += f"\nMatni xotirada yo‘q: {missing} ta."
    text += "\n\nKim o‘chirganini Telegram bildirmaydi."
    await api(session, "sendMessage", {
        "chat_id": owner_chat, "text": text,
        "reply_markup": {"inline_keyboard": [[{"text": "💬 Chatni tanlab, xabarlarni ko‘rish", "callback_data": "history:chats:0"}]]},
    })


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


def security_report_rows(store: Store, owner: int) -> list[tuple[Any, ...]]:
    return store.security_events(owner, time.time() - 7 * 86400)


async def send_security_report(
    session: aiohttp.ClientSession, store: Store, owner: int, by_chat: bool = False,
) -> None:
    try:
        events = security_report_rows(store, owner)
    except TelegramTemporaryError:
        await send_text(session, owner, "⚠️ Hisobot bazasiga hozir ulanib bo‘lmadi. Birozdan keyin qayta urinib ko‘ring.")
        return
    if not events:
        await send_text(session, owner, "📊 <b>So‘nggi 7 kun</b>\n\nHozircha qayd etilgan xavf hodisasi yo‘q.")
        return

    actions = Counter(str(row[3]) for row in events)
    categories = Counter(str(row[2]) for row in events)
    if by_chat:
        chats: Counter[tuple[int, str]] = Counter()
        for row in events:
            chats[(int(row[0]), str(row[1]))] += 1
        lines = ["💬 <b>Hodisalar chatlar bo‘yicha · 7 kun</b>", ""]
        for (chat_id, label), count in chats.most_common(10):
            lines.append(f"• {html.escape(label[:96])} — {count} ta")
    else:
        lines = [
            "📊 <b>Xavfsizlik hisoboti · 7 kun</b>",
            f"Jami xavf hodisasi: <b>{len(events)}</b>",
            f"Avtomatik o‘chirilgan: <b>{actions['auto_deleted']}</b>",
            f"Ogohlantirish yuborilgan: <b>{actions['alerted']}</b>",
            f"Akkauntingizdan ogohlantirish: <b>{actions['outgoing_warning']}</b>",
            "",
            "<b>Hodisa turlari:</b>",
        ]
        lines.extend(f"• {html.escape(category)} — {count}" for category, count in categories.most_common())
        lines.extend(["", f"Chatlar soni: <b>{len({int(row[0]) for row in events})}</b>"])
    await api(session, "sendMessage", {
        "chat_id": owner,
        "text": "\n".join(lines),
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
        "reply_markup": {"inline_keyboard": [[{"text": "🛡 Xavfsizlik markaziga qaytish", "callback_data": "center:home"}]]},
    })


async def send_security_center(
    session: aiohttp.ClientSession, store: Store, owner: int,
) -> None:
    connection_id = store.active_connection_id(owner)
    if not connection_id:
        connection_status = "🔴 Telegram Business ulanmagan"
    else:
        try:
            info = await api(session, "getBusinessConnection", {"business_connection_id": connection_id})
            store.save_connection(info)
            connection_status = "🟢 Telegram Business ulangan" if info.get("is_enabled") else "🔴 Telegram Business ulanishi o‘chiq"
        except TelegramAPIError as exc:
            if isinstance(exc, TelegramTemporaryError):
                raise
            connection_status = "⚠️ Ulanish holatini tekshirib bo‘lmadi"
    try:
        event_count = len(security_report_rows(store, owner))
    except TelegramTemporaryError:
        event_count = None
    report_status = "tekshirib bo‘lmadi" if event_count is None else f"{event_count} ta"
    history = "🟢 yoqilgan" if store.history_enabled(owner) else "⚪ o‘chiq"
    text = (
        "🛡 <b>Xavfsizlik markazi</b>\n\n"
        f"Ulanish: {connection_status}\n"
        f"Avto o‘chirish: {'🟢 yoqilgan' if store.auto_delete_enabled(owner) else '⚪ o‘chiq'}\n"
        f"Yuborilgan xabar ogohlantirishi: {'🟢 yoqilgan' if store.outgoing_warning_enabled(owner) else '⚪ o‘chiq'}\n"
        f"O‘chirilgan xabarlar tarixi: {history}\n"
        f"So‘nggi 7 kundagi hodisalar: {report_status}\n\n"
        f"Fishing domenlari bazasi: {THREAT_INTEL.status()}\n"
        f"APK xesh tekshiruvi: {'🟢 VirusTotal yoqilgan' if HASH_REPUTATION.api_key else '⚪ VirusTotal ulanmagan'}\n\n"
        "Hisobotda xabar matni, fayl yoki to‘liq havola saqlanmaydi. Faqat hodisa turi va chat bo‘yicha hisob yuritiladi."
    )
    await api(session, "sendMessage", {
        "chat_id": owner,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
        "reply_markup": {"inline_keyboard": [
            [{"text": "📊 7 kunlik hisobot", "callback_data": "center:report"},
             {"text": "💬 Chatlar bo‘yicha", "callback_data": "center:chats"}],
            [{"text": "🗑 Avto o‘chirish", "callback_data": "center:delete"},
             {"text": "⚠️ Yuborilgan xabar", "callback_data": "center:outgoing"}],
            [{"text": "📝 O‘chirilgan xabarlar", "callback_data": "center:history"}],
        ]},
    })


async def handle_security_center_callback(
    session: aiohttp.ClientSession, store: Store, query: dict[str, Any],
) -> None:
    owner = int(query["from"]["id"])
    data = str(query.get("data") or "")
    await api(session, "answerCallbackQuery", {"callback_query_id": query["id"]})
    if data == "center:home":
        await send_security_center(session, store, owner)
    elif data == "center:report":
        await send_security_report(session, store, owner)
    elif data == "center:chats":
        await send_security_report(session, store, owner, by_chat=True)
    elif data == "center:delete":
        await send_delete_mode_menu(session, store, owner)
    elif data == "center:outgoing":
        await send_outgoing_warning_menu(session, store, owner)
    elif data == "center:history":
        await send_history_menu(session, store, owner)


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
            "Avtomatik kuzatuv faylni yuklab olmaydi. Qo‘lda yuborilgan APK’ni rozilik bilan chuqur tekshirish mumkin; bu to‘liq antivirus emas.")
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
            "Havola domeni xavf bazasi va mahalliy belgilar bilan tekshiriladi; sayt ochilmaydi. 20 MB gacha APK’ni botga yuboring. Kattaroq fayl uchun pastdagi 🔬 APK tekshirish · 100 MB tugmasini bosing.")
    elif text == BUTTON_APK_UPLOAD:
        if not await offer_large_apk_upload(session, chat_id):
            await send_text(session, chat_id, "Tekshiruv sahifasi hali sozlanmagan. 20 MB gacha APK’ni shu botga yuboring.")
    elif text == BUTTON_DELETE_MODE:
        await send_delete_mode_menu(session, store, chat_id)
    elif text == BUTTON_OUTGOING_WARNING:
        await send_outgoing_warning_menu(session, store, chat_id)
    elif text == BUTTON_HISTORY:
        await send_history_menu(session, store, chat_id)
    elif text == BUTTON_SECURITY_CENTER:
        await send_security_center(session, store, chat_id)
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
    await offer_apk_inspection(session, message)


async def offer_apk_inspection(session: aiohttp.ClientSession, message: dict[str, Any]) -> None:
    document = message.get("document") or {}
    if not (str(document.get("file_name") or "").lower().endswith(".apk") or document.get("mime_type") == "application/vnd.android.package-archive"):
        return
    if any(message.get(key) for key in ("has_protected_content", "paid_media", "ttl_seconds", "self_destruct_time")):
        return
    owner = int(message["chat"]["id"])
    file_id = document.get("file_id")
    if not isinstance(file_id, str) or not 0 < len(file_id) <= 512:
        return
    size = document.get("file_size", 0)
    if type(size) is not int or size < 0 or size > MAX_UPLOAD_BYTES:
        await send_text(session, owner, "🔬 Tekshiruv uchun APK hajmi 100 MB dan oshmasligi kerak.")
        return
    if size > MAX_APK_BYTES:
        if not await offer_large_apk_upload(session, owner, str(document.get("file_name") or "yuklangan.apk")):
            await send_text(session, owner, "20 MB dan katta fayl uchun tekshiruv sahifasi sozlanishi kerak.")
        return
    now = time.monotonic()
    for token in [token for token, item in APK_REQUESTS.items() if item["expires"] <= now or item["owner"] == owner]:
        del APK_REQUESTS[token]
    token = secrets.token_urlsafe(12)
    APK_REQUESTS[token] = {"owner": owner, "file_id": file_id, "name": str(document.get("file_name") or "ilova.apk")[:128], "expires": now + 900}
    while len(APK_REQUESTS) > 100:
        APK_REQUESTS.popitem(last=False)
    await api(session, "sendMessage", {
        "chat_id": owner,
        "text": "🔬 <b>APK’ni chuqur tekshirish</b>\n\nRozilik bersangiz, bot shu faylni Telegram’dan vaqtincha xotiraga oladi, ruxsatlarini va SHA-256 xeshini tekshiradi. Fayl ishga tushirilmaydi va server diskiga saqlanmaydi. VirusTotal ulangan bo‘lsa, faqat xesh yuboriladi — fayl yuborilmaydi.\n\nTugma 15 daqiqa amal qiladi. Ruxsatlar tahlili virus yo‘qligini kafolatlamaydi.",
        "parse_mode": "HTML",
        "reply_markup": {"inline_keyboard": [[{"text": "✅ Roziman — APK’ni tekshirish", "callback_data": f"apk:scan:{token}"}]]},
    })


async def run_apk_inspection(session: aiohttp.ClientSession, owner: int, request: dict[str, Any]) -> None:
    try:
        async with APK_SCAN_SEMAPHORE:
            metadata = await api(session, "getFile", {"file_id": request["file_id"]})
            if not isinstance(metadata, dict):
                raise ValueError("Telegram fayl ma’lumoti mavjud emas")
            path = str(metadata.get("file_path") or "")
            size = metadata.get("file_size", 0)
            if not re.fullmatch(r"[A-Za-z0-9_.\-/]{1,512}", path) or path.startswith("/") or ".." in path.split("/"):
                raise ValueError("Fayl manzilini tekshirib bo‘lmadi")
            if type(size) is not int or size < 0 or size > MAX_APK_BYTES:
                raise ValueError("Fayl hajmi 20 MB dan katta")
            data = bytearray()
            async with session.get(
                f"https://api.telegram.org/file/bot{BOT_TOKEN}/{path}",
                allow_redirects=False, timeout=aiohttp.ClientTimeout(total=45),
            ) as response:
                if response.status != 200:
                    raise ValueError("Telegram’dan faylni olib bo‘lmadi")
                async for chunk in response.content.iter_chunked(65536):
                    data.extend(chunk)
                    if len(data) > MAX_APK_BYTES:
                        raise ValueError("Fayl hajmi 20 MB dan katta")
            report = await asyncio.to_thread(inspect_apk, bytes(data))
            data.clear()
            await send_apk_report(session, owner, request["name"], report)
    except (aiohttp.ClientError, asyncio.TimeoutError, TelegramAPIError, ValueError, OSError) as exc:
        # Network exception text may contain a token-bearing Telegram URL.
        log.warning("APK inspection could not finish (%s)", type(exc).__name__)
        try:
            await send_text(session, owner, "⚠️ APK tekshiruvini tugatib bo‘lmadi. Fayl 20 MB dan kichik bo‘lsin; uni botga qayta yuborib urinib ko‘ring.")
        except TelegramAPIError:
            pass


async def offer_large_apk_upload(session: aiohttp.ClientSession, owner: int, name: str = "yuklangan.apk") -> bool:
    origin = APK_UPLOAD_SERVICE.origin
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
        return False
    token = APK_UPLOAD_SERVICE.issue(owner, name)
    await api(session, "sendMessage", {
        "chat_id": owner,
        "text": "🔬 <b>100 MB gacha APK tekshirish</b>\n\nTugmani bosing, telefoningiz yoki kompyuteringizdan APK faylini tanlang va tekshirishga rozilik bering. Natija shu bot chatiga keladi.\n\nFayl vaqtinchalik server fayliga olinib, tekshiruvdan keyin o‘chiriladi. Fayl ishga tushirilmaydi. Havola faqat sizning natijangiz uchun, 15 daqiqa va bir marta amal qiladi.",
        "parse_mode": "HTML",
        "reply_markup": {"inline_keyboard": [[{"text": "📤 100 MB gacha APK yuklash", "web_app": {"url": f"{origin}/apk-upload/{token}"}}]]},
    })
    return True


async def run_uploaded_apk_inspection(session: aiohttp.ClientSession, owner: int, name: str, source) -> None:
    try:
        async with APK_SCAN_SEMAPHORE:
            worker = asyncio.create_task(asyncio.to_thread(inspect_apk_file, source))
            try:
                report = await asyncio.shield(worker)
            except asyncio.CancelledError:
                await worker
                raise
            await send_apk_report(session, owner, name, report)
    except (ValueError, OSError, TelegramAPIError) as exc:
        log.warning("Uploaded APK inspection failed (%s)", type(exc).__name__)
        try:
            await send_text(session, owner, "⚠️ Yuklangan APK’ni tekshirib bo‘lmadi. Botdan yangi havola olib qayta urinib ko‘ring.")
        except TelegramAPIError:
            pass


async def send_apk_report(session: aiohttp.ClientSession, owner: int, name: str, report: dict[str, Any]) -> None:
    reputation = await HASH_REPUTATION.lookup(session, report["sha256"])
    lines = ["🔬 <b>APK tekshiruvi</b>", html.escape(name), ""]
    if report["manifest_read"]:
        lines.append("<b>Kuchli ruxsatlar:</b>")
        lines.extend("• " + RISK_PERMISSIONS[p] for p in report["permissions"])
        if not report["permissions"]:
            lines.append("Tekshirilgan kuchli ruxsatlar topilmadi.")
        lines.append("Bu ruxsatlar foydali ilovalarda ham bo‘lishi mumkin; ular virus ekanini isbotlamaydi.")
    else:
        lines.append("⚠️ APK manifestini o‘qib bo‘lmadi. Fayl buzilgan, boshqa turda yoki qo‘llab-quvvatlanmaydigan bo‘lishi mumkin.")
    lines.append("")
    if reputation["status"] == "found":
        lines.append(f"<b>VirusTotal hisoboti:</b> {reputation['malicious']} zararli, {reputation['suspicious']} shubhali belgi.")
        if not reputation["malicious"] and not reputation["suspicious"]:
            lines.append("Bazadagi tekshiruvda zararli belgi topilmagan. Bu xavfsizlik kafolati emas.")
        else:
            lines.append("⚠️ Ushbu faylni o‘rnatmang; bazada xavf belgilari bor.")
    else:
        status_text = {"disabled": "Virus bazasi ulanmagan. Hozir faqat mahalliy ruxsatlar tahlili bajarildi.",
                       "not_found": "Bu fayl xeshi VirusTotal bazasida topilmadi. Xavfsiz deb hisoblamang.",
                       "rate_limited": "VirusTotal tekshiruvi limiti tugagan. Mahalliy tahlil bajarildi.",
                       "unavailable": "VirusTotal hozir javob bermadi. Mahalliy tahlil bajarildi."}
        lines.append("⚠️ " + status_text[reputation["status"]])
    lines.extend(["", "SHA-256:", "<code>" + report["sha256"] + "</code>", "", "Fayl ishga tushirilmadi va tashqi skanerga yuklanmadi."])
    await send_text(session, owner, "\n".join(lines))


async def handle_apk_callback(session: aiohttp.ClientSession, query: dict[str, Any]) -> None:
    owner = int(query["from"]["id"])
    token = str(query.get("data") or "").removeprefix("apk:scan:")
    request = APK_REQUESTS.get(token)
    if not request or request["owner"] != owner or request["expires"] <= time.monotonic():
        await api(session, "answerCallbackQuery", {"callback_query_id": query["id"], "text": "So‘rov eskirgan. APK’ni botga qayta yuboring.", "show_alert": True})
        return
    if len(APK_SCAN_JOBS) >= 4 or not APK_SCAN_LIMITER.allow(("apk", owner)):
        await api(session, "answerCallbackQuery", {"callback_query_id": query["id"], "text": "Tekshiruv band yoki limit tugagan. Bir soatda 3 ta APK tekshiriladi.", "show_alert": True})
        return
    APK_REQUESTS.pop(token)
    await api(session, "answerCallbackQuery", {"callback_query_id": query["id"], "text": "Tekshiruv boshlandi. Natija shu chatga keladi."})
    task = asyncio.create_task(run_apk_inspection(session, owner, request))
    APK_SCAN_JOBS.add(task)
    task.add_done_callback(APK_SCAN_JOBS.discard)


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
    if "deleted_business_messages" in update:
        await handle_business_deletions(session, store, update["deleted_business_messages"])
        return
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
        connection_id = update["business_connection"]["id"]
        info = await api(session, "getBusinessConnection", {"business_connection_id": connection_id})
        if not isinstance(info, dict) or info.get("id") != connection_id:
            raise TelegramAPIError("Business ulanishini tasdiqlab bo‘lmadi")
        store.save_connection(info)
        if not info.get("is_enabled"):
            DELETED_HISTORY.clear(int((info.get("user") or {}).get("id", 0)))
        log.info("Business ulanish holati yangilandi")
        return

    if "callback_query" in update:
        query = update["callback_query"]
        data = query.get("data", "")
        if data.startswith("apk:scan:"):
            await handle_apk_callback(session, query)
            return
        if data.startswith("center:"):
            await handle_security_center_callback(session, store, query)
            return
        if data.startswith("history:"):
            await handle_history_callback(session, store, query)
            return
        if data.startswith(("photo_test:", "unknown_sender:", "trust_sender:")):
            await api(session, "answerCallbackQuery", {
                "callback_query_id": query["id"], "text": "Bu bo‘lim olib tashlangan.",
            })
            await send_text(session, int(query["from"]["id"]), "🛡 Menyu yangilandi. Kerakli bo‘limni pastdan tanlang.")
            return
        toggle_setting = None
        if data in {"delete_mode:on", "delete_mode:off"}:
            toggle_setting = "delete_mode"
        elif data in {"outgoing_warning:on", "outgoing_warning:off"}:
            toggle_setting = "outgoing_warning"
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
    if not await business_subscription_allowed(session, owner_user_id, owner_chat_id):
        return

    # Business updates include incoming and outgoing messages. Warn the recipient
    # under risky messages sent from the owner's account; alert the owner about
    # risky incoming messages. Ignore messages generated by this bot to avoid loops.
    if (message.get("chat") or {}).get("type") != "private":
        return
    sender_id = (message.get("from") or {}).get("id")
    if message.get("sender_business_bot"):
        return

    if sender_id and sender_id != owner_user_id and store.history_enabled(owner_user_id):
        DELETED_HISTORY.remember(owner_user_id, str(connection_id), message)

    result = analyze(message)
    if not result:
        return
    if sender_id == owner_user_id:
        warning_reason = business_outgoing_warning_reason(message, result)
        if store.outgoing_warning_enabled(owner_user_id) and warning_reason:
            await warn_recipient_about_suspicious_outgoing(
                session, owner_chat_id, message, str(connection_id), result
            )
            store.record_security_event(
                owner_user_id, str(connection_id), int(message["chat"]["id"]),
                security_chat_label(message), security_event_category(message, result),
                "outgoing_warning", int(result.get("score", 0)),
            )
        return

    if store.auto_delete_enabled(owner_user_id):
        reason = business_deletion_reason(message, result)
        if reason and await delete_incoming_business_message(
            session, owner_chat_id, str(connection_id), message, reason,
        ):
            if store.history_enabled(owner_user_id):
                DELETED_HISTORY.remember(owner_user_id, str(connection_id), message, ignored=True)
            store.record_security_event(
                owner_user_id, str(connection_id), int(message["chat"]["id"]),
                security_chat_label(message), security_event_category(message, result),
                "auto_deleted", int(result.get("score", 0)),
            )
            return

    await api(session, "sendMessage", {
        "chat_id": owner_chat_id,
        "text": alert_message(result),
        "parse_mode": "HTML",
        "reply_markup": alert_keyboard(result),
        "disable_web_page_preview": True,
    })
    store.record_security_event(
        owner_user_id, str(connection_id), int(message["chat"]["id"]),
        security_chat_label(message), security_event_category(message, result),
        "alerted", int(result.get("score", 0)),
    )
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
    if kind == "deleted_business_messages":
        string(value.get("business_connection_id"), 256)
        chat = obj(value.get("chat"))
        if not integer(chat.get("id")) or chat.get("type") != "private":
            raise ValueError("Invalid deleted chat")
        ids = value.get("message_ids")
        if not isinstance(ids, list) or any(not integer(item, True) for item in ids):
            raise ValueError("Invalid deleted message ids")
        return
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
    private_owner = int(message["chat"]["id"]) if message and message["chat"]["type"] == "private" else None
    if query:
        private_owner = int(query["from"]["id"])
    privacy_action = query and query.get("data") in {"history:off", "history:clear"}
    if private_owner and not privacy_action:
        recheck = query and query.get("data") == "subscription:check"
        if recheck:
            await api(session, "answerCallbackQuery", {"callback_query_id": query["id"], "text": "Obuna tekshirilmoqda…"})
        state = await subscription_state(session, private_owner, force=True)
        if state != "member":
            if query and not recheck:
                await api(session, "answerCallbackQuery", {"callback_query_id": query["id"], "text": "Avval kanal obunasini tasdiqlang."})
            await send_subscription_prompt(session, private_owner, state)
            store.mark_update_processed(update_id)
            return
        if recheck:
            await handle_start(session, private_owner)
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
            DELETED_HISTORY.prune()
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


MINIAPP_HTML = '<!doctype html><html lang="uz" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Qalqon AI</title><script src="https://telegram.org/js/telegram-web-app.js"></script><style>\n:root{--bg:#080f1f;--panel:#101d33;--raised:#192b46;--ink:#f1f7ff;--sub:#9aafc9;--line:#233852;--mint:#68caff;--mint-ink:#062444;--mint-bg:#123655;--red:#ff9c90;--red-bg:#3b292b;--amber:#f2c481;--amber-bg:#3e3325;--blue:#9fc9ff;--blue-bg:#27364b;--shadow:0 24px 80px #0004;--radius:22px;--nav:83px}\n[data-theme=light]{--bg:#f1f6ff;--panel:#fff;--raised:#eaf2ff;--ink:#102747;--sub:#607693;--line:#d9e6f7;--mint:#1469d4;--mint-ink:#fff;--mint-bg:#e1efff;--red:#b34034;--red-bg:#ffede8;--amber:#92601e;--amber-bg:#fff2df;--blue:#376aa8;--blue-bg:#e9f0ff;--shadow:0 24px 80px #173f790d}\n*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 Inter,"Segoe UI",system-ui,-apple-system,sans-serif;-webkit-font-smoothing:antialiased;transition:background .2s,color .2s}button,input{font:inherit}button,a{-webkit-tap-highlight-color:transparent}button{color:inherit;border:0;background:none;cursor:pointer}a{color:inherit;text-decoration:none}button:focus-visible,a:focus-visible,input:focus-visible{outline:3px solid var(--mint);outline-offset:4px}button:disabled{cursor:default;opacity:.5}svg.icon{width:22px;height:22px;stroke:currentColor;stroke-width:1.7;fill:none;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}.muted{color:var(--sub)}.mint{color:var(--mint)}.tiny{font-size:12px}.small{font-size:14px}.eyebrow{font-size:11px;font-weight:750;letter-spacing:.13em;text-transform:uppercase;color:var(--sub)}h1,h2,h3,p{margin:0}h1{font-size:30px;line-height:1.2;letter-spacing:-1px;font-weight:700}h2{font-size:19px;letter-spacing:-.35px}h3{font-size:16px}b,strong{font-weight:650}.screen-title{margin:24px 0 27px}.screen-title p{color:var(--sub);margin-top:9px;font-size:15px}.app{min-height:100dvh}.sidebar{position:fixed;inset:0 auto 0 0;width:240px;border-right:1px solid var(--line);padding:34px 23px;display:flex;flex-direction:column;background:var(--bg);z-index:30}.brand{display:flex;align-items:center;gap:11px}.brand-mark{width:41px;height:45px;display:grid;place-items:center;color:var(--mint);background:var(--mint-bg);border-radius:13px}.brand-mark svg{width:29px;height:30px}.brand-name{font-weight:760;font-size:20px;letter-spacing:-.6px}.brand-sub{color:var(--sub);font-size:11px}.side-menu{display:grid;gap:7px;margin-top:60px}.side-menu button{display:flex;align-items:center;gap:13px;padding:14px 16px;border-radius:13px;color:var(--sub);font-size:15px;text-align:left}.side-menu button.active{background:var(--mint-bg);color:var(--mint);font-weight:600}.side-menu button:hover{background:var(--panel)}.side-bottom{margin-top:auto}.side-caption{font-size:12px;color:var(--sub);margin:26px 12px}.profile-mini{padding:15px 10px;border-top:1px solid var(--line);display:flex;gap:12px;align-items:center}.avatar{width:43px;height:43px;border-radius:15px;background:var(--blue-bg);color:var(--blue);display:grid;place-items:center;font-size:14px;font-weight:650;flex-shrink:0}.avatar.mint-avatar{background:var(--mint-bg);color:var(--mint)}.avatar.amber-avatar{background:var(--amber-bg);color:var(--amber)}.avatar.rose-avatar{background:var(--red-bg);color:var(--red)}.main-shell{margin-left:240px}.topbar{max-width:1100px;margin:auto;padding:26px 36px 0;display:flex;align-items:center;justify-content:space-between;gap:10px}.topbar .mobile-brand{display:none}.demo-badge{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--sub);border:1px solid var(--line);border-radius:99px;padding:6px 11px;white-space:nowrap}.demo-badge:before{content:"";width:6px;height:6px;background:var(--amber);border-radius:50%}.top-actions{display:flex;gap:8px}.icon-btn{width:41px;height:41px;display:grid;place-items:center;border-radius:50%;border:1px solid var(--line);background:var(--panel);position:relative}.icon-btn .dot{position:absolute;right:10px;top:8px;width:6px;height:6px;background:var(--mint);border:1px solid var(--panel);border-radius:50%}.content{max-width:1100px;margin:auto;padding:6px 36px 45px}.page{animation:appear .3s ease both}@keyframes appear{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:none}}.page-head{display:flex;align-items:center;justify-content:space-between;margin-top:21px}.page-head .small{color:var(--sub)}.intro{margin:18px 0 24px;display:flex;align-items:end;justify-content:space-between}.intro h1{margin-top:7px}.intro .date{font-size:13px;color:var(--sub)}.grid-home{display:grid;grid-template-columns:1.15fr 1fr;gap:24px;align-items:start}.hero{background:linear-gradient(125deg,#96edcd,#c0f4d3);border-radius:25px;color:#173e2f;min-height:265px;padding:27px;position:relative;overflow:hidden;isolation:isolate}.hero:before{content:"";position:absolute;width:250px;height:250px;border:1px solid #1e64441a;border-radius:50%;right:-45px;top:8px;z-index:-1}.hero:after{content:"";position:absolute;width:185px;height:185px;border:1px solid #1e64441a;border-radius:50%;right:-12px;top:41px;z-index:-1}.hero-status{display:inline-flex;gap:6px;align-items:center;font-size:11px;font-weight:650;background:#155b3d14;padding:5px 10px;border-radius:99px}.status-dot{height:6px;width:6px;border-radius:50%;background:currentColor}.hero h2{font-size:27px;line-height:1.2;max-width:235px;letter-spacing:-.8px;margin-top:20px}.hero p{font-size:13px;max-width:210px;color:#335e4b;margin-top:10px}.hero .hero-shield{position:absolute;right:13px;top:72px;width:138px;height:150px;filter:drop-shadow(0 15px 16px #12674920);pointer-events:none}.hero .hero-shield path.outer{fill:#e1ffeb;stroke:#4ea278;stroke-width:1}.hero .hero-shield path.inner{fill:#3b9068;stroke:#246c4b;stroke-width:1}.hero .hero-shield path.check{fill:none;stroke:#f0fff3;stroke-width:6;stroke-linecap:round;stroke-linejoin:round}.hero-link{display:inline-flex;gap:8px;align-items:center;font-size:12px;font-weight:700;margin-top:21px;border-bottom:1px solid #326c5050;padding:0 0 4px}.hero-link svg{width:16px;height:16px}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin-top:16px}.stat{padding:17px 12px;background:var(--panel);border:1px solid var(--line);border-radius:16px}.stat .stat-icon{color:var(--sub);margin-bottom:8px;display:flex}.stat .value{font-size:27px;font-weight:680;letter-spacing:-.8px}.stat .label{font-size:11px;line-height:1.35;color:var(--sub);margin-top:4px}.stat:nth-child(2) .stat-icon{color:var(--amber)}.stat:nth-child(3) .stat-icon{color:var(--red)}.section-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:15px;gap:10px}.text-link{color:var(--mint);font-size:12px;font-weight:600;display:flex;gap:4px;align-items:center;white-space:nowrap}.text-link svg{width:15px;height:15px}.quick-scan{display:flex;gap:15px;align-items:center;padding:20px 18px;background:var(--panel);border:1px solid var(--line);border-radius:20px;width:100%;text-align:left;transition:border-color .2s,transform .2s}.quick-scan:hover{border-color:var(--mint);transform:translateY(-2px)}.square-icon{width:47px;height:47px;border-radius:15px;display:grid;place-items:center;background:var(--mint-bg);color:var(--mint);flex-shrink:0}.square-icon.red{background:var(--red-bg);color:var(--red)}.square-icon.amber{background:var(--amber-bg);color:var(--amber)}.square-icon.blue{background:var(--blue-bg);color:var(--blue)}.quick-scan h3{font-size:15px}.quick-scan p{font-size:12px;color:var(--sub);margin-top:4px}.push{margin-left:auto}.events-section{margin-top:28px}.row-list{background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:3px 17px}.event-row{display:flex;align-items:center;gap:12px;padding:16px 0;border-bottom:1px solid var(--line);text-align:left;width:100%}.event-row:last-child{border:0}.event-row .square-icon{width:39px;height:39px;border-radius:12px}.event-row h3{font-size:13px}.event-row p{font-size:11px;color:var(--sub);margin-top:3px}.event-row time{font-size:11px;color:var(--sub);margin-left:auto;align-self:center;white-space:nowrap}.soft-note{display:flex;gap:9px;color:var(--sub);font-size:11px;margin:20px 2px 0;align-items:start}.soft-note svg{width:15px;height:15px;flex-shrink:0;margin-top:2px}.bottom-nav{display:none}.split{display:grid;grid-template-columns:1fr 1fr;gap:24px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:24px}.segmented{display:flex;gap:5px;padding:5px;background:var(--panel);border:1px solid var(--line);border-radius:15px;margin-bottom:22px}.segmented button{flex:1;display:flex;align-items:center;justify-content:center;gap:8px;padding:11px 8px;border-radius:10px;color:var(--sub);font-size:14px}.segmented button.active{background:var(--raised);color:var(--ink);box-shadow:0 2px 4px #0001}.segmented svg{width:18px;height:18px}.field-label{font-size:13px;font-weight:650;display:block;margin-bottom:10px}.input-wrap{display:flex;gap:10px;align-items:center;background:var(--bg);border:1px solid var(--line);border-radius:13px;padding:13px 15px}.input-wrap svg{color:var(--sub);width:19px;height:19px}input{width:100%;border:0;background:none;color:var(--ink);outline:0!important;min-width:0;font-size:15px}input::placeholder{color:var(--sub);opacity:.8}.input-wrap:focus-within{border-color:var(--mint);box-shadow:0 0 0 3px #68caff1a}.field-error{color:var(--red);font-size:12px;min-height:23px;padding:6px 0}.button{display:flex;align-items:center;justify-content:center;gap:9px;padding:14px 18px;min-height:49px;border-radius:13px;font-size:14px;font-weight:650;transition:transform .15s,background .2s}.button:active{transform:scale(.98)}.button.primary{background:var(--mint);color:var(--mint-ink)}.button.secondary{background:var(--raised);color:var(--ink)}.button.danger{color:var(--red);background:var(--red-bg)}.button.full{width:100%}.button svg{height:19px;width:19px}.examples{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:16px}.chip{font-size:11px;padding:6px 10px;border-radius:8px;border:1px solid var(--line);color:var(--sub)}.chip.active{background:var(--mint-bg);border-color:transparent;color:var(--mint)}.scan-info{display:grid;gap:22px}.info-item{display:flex;gap:13px;align-items:start}.info-item .square-icon{width:36px;height:36px;border-radius:11px}.info-item h3{font-size:14px}.info-item p{font-size:12px;line-height:1.6;color:var(--sub);margin-top:4px}.upload-zone{position:relative;display:flex;flex-direction:column;align-items:center;justify-content:center;border:1px dashed var(--sub);border-radius:17px;min-height:190px;text-align:center;padding:24px;cursor:pointer;background:var(--bg)}.upload-zone .square-icon{margin-bottom:15px}.upload-zone input{position:absolute;inset:0;opacity:0;width:100%;height:100%;cursor:pointer}.upload-zone h3{font-size:14px;max-width:100%;overflow-wrap:anywhere}.upload-zone p{font-size:12px;color:var(--sub);margin-top:7px}.tag{display:inline-flex;align-items:center;gap:5px;padding:5px 9px;border-radius:8px;background:var(--mint-bg);color:var(--mint);font-size:11px;font-weight:600}.tag.red{background:var(--red-bg);color:var(--red)}.tag.amber{background:var(--amber-bg);color:var(--amber)}.scan-result{margin-top:22px}.result-title{display:flex;gap:12px;align-items:center;margin-bottom:18px}.result-title h3{font-size:17px}.result-title p{font-size:11px;color:var(--sub);margin-top:4px}.result-row{display:flex;justify-content:space-between;gap:16px;padding:14px 0;border-bottom:1px solid var(--line);font-size:13px}.result-row:last-child{border:0}.result-row span:last-child{color:var(--sub);text-align:right;overflow-wrap:anywhere;max-width:65%}.result-footer{padding:13px;background:var(--bg);border-radius:12px;color:var(--sub);font-size:12px;line-height:1.6;margin-top:18px}.loading-line{height:4px;overflow:hidden;border-radius:4px;background:var(--line);margin-top:14px}.loading-line:before{content:"";display:block;height:4px;width:40%;border-radius:4px;background:var(--mint);animation:loading 1s infinite ease-in-out}@keyframes loading{from{transform:translateX(-100%)}to{transform:translateX(350%)}}.search-bar{margin-bottom:18px}.filters{display:flex;gap:8px;margin-bottom:22px}.filters button{border:1px solid var(--line);border-radius:99px;padding:7px 15px;color:var(--sub);font-size:12px}.filters button.active{background:var(--mint-bg);border-color:transparent;color:var(--mint)}.chat-list{display:grid;gap:0;background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:0 18px}.chat-row{padding:20px 0;display:flex;gap:13px;align-items:center;border-bottom:1px solid var(--line);text-align:left;width:100%}.chat-row:last-child{border:0}.chat-row h3{font-size:15px}.chat-row p{font-size:12px;color:var(--sub);margin-top:4px}.chat-meta{margin-left:auto;text-align:right;white-space:nowrap}.chat-meta .count{background:var(--mint-bg);color:var(--mint);display:inline-grid;place-items:center;min-width:24px;height:24px;border-radius:8px;font-size:11px}.chat-meta time{display:block;font-size:10px;color:var(--sub);margin-top:6px}.back-button{display:flex;gap:7px;align-items:center;color:var(--sub);font-size:13px;margin:24px 0 20px}.back-button svg{width:17px;height:17px}.chat-header{display:flex;gap:14px;align-items:center;margin-bottom:22px}.chat-header h1{font-size:23px}.chat-header p{color:var(--sub);font-size:12px;margin-top:4px}.messages-stack{display:flex;flex-direction:column;gap:16px;max-width:650px}.message-bubble{border:1px solid var(--line);background:var(--panel);border-radius:18px 18px 18px 4px;padding:17px;max-width:90%;align-self:start;min-width:210px}.message-bubble p{font-size:15px}.message-bubble .message-caption{font-size:10px;color:var(--sub);display:flex;gap:6px;align-items:center;margin-top:12px;justify-content:space-between}.message-caption svg{width:13px;height:13px}.media-example{background:linear-gradient(130deg,#254d4b,#47667b);height:130px;border-radius:11px;display:grid;place-items:center;color:#d5e8e3;margin-bottom:12px}.media-example svg{height:32px;width:32px}.voice-example{display:flex;align-items:center;gap:10px;margin:6px 0}.voice-example button{background:var(--mint-bg);border-radius:50%;height:36px;width:36px;display:grid;place-items:center;color:var(--mint)}.wave{height:25px;display:flex;align-items:center;gap:3px}.wave i{width:3px;border-radius:3px;background:var(--mint);height:var(--h)}.playing .wave i{animation:wave .6s ease infinite alternate;animation-delay:var(--d)}@keyframes wave{to{height:5px}}.detail-actions{display:flex;gap:10px;margin-top:24px}.empty-state{text-align:center;padding:42px 24px}.empty-state .square-icon{margin:0 auto 18px;width:62px;height:62px;border-radius:20px}.empty-state h3{font-size:18px}.empty-state p{font-size:13px;color:var(--sub);margin:10px auto 24px;max-width:290px}.report-stats{display:grid;grid-template-columns:repeat(2,1fr);gap:14px;margin-bottom:22px}.report-stat{padding:22px;background:var(--panel);border:1px solid var(--line);border-radius:18px}.report-stat .value{font-size:31px;letter-spacing:-1px;font-weight:650;margin-top:11px}.report-stat .label{font-size:12px;color:var(--sub)}.report-stat svg{color:var(--mint)}.report-stat:nth-child(2) svg{color:var(--amber)}.chart-head{display:flex;justify-content:space-between;align-items:start;margin-bottom:20px}.chart-head p{font-size:11px;color:var(--sub);margin-top:4px}.chart-head .tag{padding:4px 7px;font-size:10px}.chart{height:177px;display:flex;gap:10px;align-items:end;position:relative;padding-top:20px;border-bottom:1px solid var(--line);background:repeating-linear-gradient(to top,transparent 0,transparent 43px,var(--line) 44px,transparent 45px)}.bar-column{flex:1;height:100%;display:flex;justify-content:flex-end;align-items:center;flex-direction:column;gap:0;position:relative;min-width:0}.bar-column .bar{width:70%;max-width:32px;min-height:0;background:var(--mint);border-radius:6px 6px 0 0;opacity:.6;transition:opacity .2s,height .3s}.bar-column:last-child .bar,.bar-column:hover .bar{opacity:1}.bar-column .warn-bar{position:absolute;bottom:0;width:70%;max-width:32px;background:var(--amber);border-radius:5px 5px 0 0}.chart-labels{display:flex;gap:10px;margin:10px 0 0}.chart-labels span{flex:1;text-align:center;font-size:10px;color:var(--sub)}.chart-labels span:last-child{color:var(--mint)}.chart-value{font-size:10px;color:var(--ink);background:var(--raised);padding:3px 6px;border-radius:5px;position:absolute;top:0;opacity:0;transform:translateY(-4px);transition:.2s}.bar-column:hover .chart-value,.bar-column:focus-visible .chart-value{opacity:1}.chart-legend{display:flex;gap:17px;align-items:center;font-size:10px;color:var(--sub);margin-top:22px}.legend-dot{display:inline-block;height:6px;width:6px;border-radius:50%;background:var(--mint);margin-right:6px}.legend-dot.amber{background:var(--amber)}.categories{margin-top:22px}.category-row{display:flex;align-items:center;gap:12px;padding:15px 0;border-bottom:1px solid var(--line)}.category-row:last-child{border:0}.category-row .square-icon{height:34px;width:34px;border-radius:10px}.category-row span{font-size:13px}.category-row b{margin-left:auto;font-size:14px}.profile-panel{display:flex;gap:14px;align-items:center;padding:22px 0;border-bottom:1px solid var(--line);margin-bottom:22px}.profile-panel .avatar{width:56px;height:56px;border-radius:18px;font-size:22px;background:var(--mint-bg);color:var(--mint)}.profile-panel h2{font-size:19px}.profile-panel p{font-size:12px;color:var(--sub);margin-top:3px}.settings-group{background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:0 18px;margin-bottom:21px}.setting-row{display:flex;align-items:center;gap:13px;padding:19px 0;border-bottom:1px solid var(--line)}.setting-row:last-child{border:0}.setting-row .square-icon{width:38px;height:38px;border-radius:12px}.setting-row h3{font-size:13px}.setting-row p{font-size:11px;color:var(--sub);margin-top:4px;max-width:240px;line-height:1.45}.switch{width:43px;height:26px;flex-shrink:0;border-radius:99px;background:var(--line);margin-left:auto;padding:3px;transition:.2s}.switch:after{content:"";display:block;width:20px;height:20px;border-radius:50%;background:var(--sub);transform:translateX(0);transition:.2s}.switch.on{background:var(--mint)}.switch.on:after{transform:translateX(17px);background:var(--mint-ink)}.setting-row .arrow-btn{margin-left:auto;flex-shrink:0;color:var(--sub);padding:8px 0 8px 8px}.setting-row .arrow-btn svg{width:17px;height:17px}.theme-options{display:flex;gap:7px;margin-left:auto}.theme-option{border:1px solid var(--line);height:35px;width:35px;display:grid;place-items:center;border-radius:11px;color:var(--sub)}.theme-option.active{border-color:var(--mint);color:var(--mint);background:var(--mint-bg)}.theme-option svg{width:18px;height:18px}.app-version{text-align:center;color:var(--sub);font-size:11px;margin:20px}.design-note{padding:13px 16px;background:var(--mint-bg);border-radius:12px;color:var(--mint);font-size:11px;display:flex;gap:8px;align-items:center}.design-note svg{width:15px;height:15px}.modal-backdrop{position:fixed;inset:0;background:#0308119c;z-index:70;display:flex;align-items:center;justify-content:center;padding:22px;backdrop-filter:blur(6px);animation:appear .2s}.modal{width:min(100%,480px);max-height:88dvh;overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:26px;padding:26px;box-shadow:var(--shadow)}.modal-head{display:flex;align-items:center;justify-content:space-between;gap:15px;margin-bottom:22px}.modal-head h2{font-size:20px}.modal-head .icon-btn{width:34px;height:34px;background:var(--raised)}.modal p{font-size:14px;line-height:1.65;color:var(--sub)}.modal .button{margin-top:13px}.modal .square-icon{margin-bottom:18px}.modal ul{padding-left:18px;font-size:13px;color:var(--sub);line-height:1.8}.step{display:flex;gap:13px;margin-bottom:22px}.step-number{height:29px;width:29px;display:grid;place-items:center;background:var(--mint-bg);color:var(--mint);border-radius:10px;flex-shrink:0;font-size:12px;font-weight:700}.step h3{font-size:14px}.step p{font-size:12px;margin-top:5px}.toast{position:fixed;bottom:28px;left:calc(50% + 120px);transform:translate(-50%,20px);background:var(--ink);color:var(--bg);font-size:13px;padding:13px 19px;border-radius:13px;box-shadow:var(--shadow);z-index:100;opacity:0;transition:.2s;pointer-events:none;max-width:90vw;text-align:center}.toast.show{opacity:1;transform:translate(-50%,0)}.mobile-only{display:none}.scroll-row{display:flex;align-items:center;gap:12px}.control-label{font-size:12px;color:var(--sub);margin-bottom:10px}.footer-gap{height:10px}\n@media(min-width:1200px){.hero{min-height:282px}.hero h2{font-size:30px;max-width:240px}.hero .hero-shield{right:20px;width:149px;height:160px}.hero p{max-width:230px}.grid-home{grid-template-columns:1.1fr 1fr}}\n@media(max-width:1000px) and (min-width:701px){.sidebar{width:200px;padding:28px 17px}.main-shell{margin-left:200px}.topbar{padding:24px 24px 0}.content{padding:6px 24px 35px}.grid-home,.split{grid-template-columns:1fr}.hero .hero-shield{right:40px}.hero h2{max-width:60%}.hero p{max-width:55%}.toast{left:calc(50% + 100px)}}\n@media(max-width:700px){:root{--nav:82px}.sidebar{display:none}.main-shell{margin:0}.topbar{padding:20px 21px 0;gap:8px}.topbar .mobile-brand{display:flex}.brand-name{font-size:20px}.brand-mark{width:35px;height:38px;border-radius:11px}.brand-mark svg{width:25px;height:28px}.brand-sub{font-size:9px}.topbar>.demo-badge{display:none}.top-actions{gap:7px}.icon-btn{width:36px;height:36px}.icon-btn svg{width:19px;height:19px}.content{padding:7px 21px calc(var(--nav) + 28px + env(safe-area-inset-bottom))}.mobile-only{display:flex}.demo-line{margin-top:17px;align-items:center;justify-content:space-between;font-size:10px;color:var(--sub)}.demo-line .demo-badge{font-size:10px;padding:4px 9px}.intro{margin:23px 0 20px}.intro .date{display:none}.eyebrow{font-size:10px}.intro h1{font-size:28px;letter-spacing:-1px}.grid-home,.split{grid-template-columns:1fr;gap:24px}.hero{min-height:247px;padding:24px}.hero-status{font-size:10px}.hero h2{font-size:27px;max-width:210px;margin-top:20px}.hero p{font-size:12px;max-width:185px}.hero .hero-shield{width:122px;height:137px;right:6px;top:78px}.hero-link{font-size:11px;margin-top:21px}.stats{margin-top:14px;gap:9px}.stat{padding:15px 11px;border-radius:16px}.stat .value{font-size:25px}.stat .stat-icon{margin-bottom:5px}.stat .stat-icon svg{width:17px;height:17px}.stat .label{font-size:10px}.section-head h2{font-size:17px}.home-right .section-head{margin-bottom:13px}.quick-scan{padding:17px 15px;border-radius:18px}.quick-scan h3{font-size:14px}.quick-scan p{font-size:11px}.square-icon{width:42px;height:42px;border-radius:13px}.events-section{margin-top:25px}.row-list{padding:2px 15px;border-radius:18px}.event-row{padding:15px 0;gap:10px}.event-row h3{font-size:12px}.event-row p{font-size:10px}.event-row time{font-size:10px}.event-row .square-icon{width:35px;height:35px;border-radius:11px}.soft-note{font-size:10px;margin-top:17px}.bottom-nav{display:flex;position:fixed;bottom:0;left:0;right:0;border-top:1px solid var(--line);background:color-mix(in srgb,var(--bg) 94%,transparent);backdrop-filter:blur(20px);padding:10px 10px calc(11px + env(safe-area-inset-bottom));z-index:40;justify-content:space-around;gap:0}.bottom-nav button{color:var(--sub);font-size:9px;display:flex;align-items:center;justify-content:center;gap:5px;flex-direction:column;min-width:0;min-height:48px;flex:1;position:relative}.bottom-nav button svg{width:21px;height:21px}.bottom-nav button.active{color:var(--mint)}.bottom-nav button.active:before{content:"";position:absolute;top:-11px;background:var(--mint);width:20px;height:2px;border-radius:2px}.screen-title{margin:25px 0 23px}.screen-title h1{font-size:28px}.screen-title p{font-size:13px;max-width:300px}.panel{padding:20px;border-radius:20px}.scan-info{gap:20px;padding:0 2px}.segmented{margin-bottom:20px}.segmented button{font-size:13px;padding:9px}.field-label{font-size:12px}.button{font-size:13px}.report-stats{gap:11px}.report-stat{padding:18px}.report-stat .value{font-size:29px}.report-stat .label{font-size:11px}.chat-list{padding:0 15px}.chat-row{padding:19px 0}.chat-row h3{font-size:14px}.chat-row p{font-size:11px}.profile-panel{margin-top:-8px}.settings-group{padding:0 15px}.setting-row{gap:11px;padding:18px 0}.setting-row h3{font-size:12px}.setting-row p{font-size:10px;max-width:215px}.setting-row .square-icon{width:34px;height:34px;border-radius:10px}.switch{width:40px;height:25px;padding:3px}.switch:after{width:19px;height:19px}.switch.on:after{transform:translateX(15px)}.modal-backdrop{align-items:flex-end;padding:0}.modal{width:100%;border-radius:26px 26px 0 0;max-height:88dvh;padding:25px 23px calc(27px + env(safe-area-inset-bottom))}.modal:before{content:"";display:block;width:35px;height:4px;background:var(--line);border-radius:4px;margin:-13px auto 22px}.toast{bottom:calc(var(--nav) + 14px + env(safe-area-inset-bottom));left:50%;min-width:240px}.messages-stack{max-width:100%}.message-bubble{max-width:95%}.detail-actions{flex-direction:column}.design-note{font-size:10px}.chart{height:170px}.mobile-only{display:flex}.categories{margin-top:0}}\n@media(max-width:370px){.content{padding-left:17px;padding-right:17px}.topbar{padding-left:17px;padding-right:17px}.hero{padding:21px}.hero h2{font-size:25px;max-width:190px}.hero .hero-shield{width:106px;right:0;top:80px}.hero p{max-width:172px}.stat{padding:13px 9px}.bottom-nav button{font-size:8px}.setting-row p{max-width:175px}.brand-sub{display:none}}\n@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important;scroll-behavior:auto!important}}\n.tag{white-space:nowrap}.switch{position:relative}.switch:before{content:"";position:absolute;inset:-9px -3px}.arrow-btn{min-width:36px;min-height:40px}\n@media(max-width:700px){html{scrollbar-width:none}body::-webkit-scrollbar{display:none}.bottom-nav button{font-size:10px}.stat .label{font-size:11px}.quick-scan h3{font-size:15px}.quick-scan p{font-size:12px}.event-row h3{font-size:14px}.event-row p{font-size:11px}.event-row time{font-size:11px}.soft-note{font-size:11px}.setting-row h3{font-size:14px}.setting-row p{font-size:12px}.setting-row{gap:10px}.setting-row p{max-width:205px}.setting-row .square-icon{width:32px;height:32px}.field-label{font-size:14px}.chat-row h3{font-size:15px}.chat-row p{font-size:12px}.chat-header .tag{font-size:10px}.profile-panel p{font-size:11px}.design-note{font-size:11px}}\n\n/* Qalqon blue visual system */\nbody{background:radial-gradient(ellipse at 80% 0%,#164b7d22,transparent 50%),var(--bg)}\n.brand-mark{background:linear-gradient(145deg,#133a68,#07182e);color:#72d9ff;border:1px solid #459edb65;box-shadow:inset 0 1px 1px #a9eaff30,0 0 24px #168aff18;border-radius:14px}\n.brand-mark svg{filter:drop-shadow(0 0 5px #2faeff80)}\n.hero{background:radial-gradient(circle at 90% 45%,#148cd955,transparent 40%),linear-gradient(125deg,#103f7c,#105da3 65%,#087caa);color:#f4faff;border:1px solid #3d9ee080;box-shadow:inset 0 1px #ffffff19,0 18px 45px #003a8425}\n.hero:before,.hero:after{border-color:#92deff25}\n.hero-status{background:#051e4660;color:#d7f2ff;border:1px solid #9bdfff25}\n.hero p{color:#c0ddf6}.hero-link{border-color:#a3dcff70;color:#fff}\n.hero .status-dot{background:#88e4ff;box-shadow:0 0 10px #63ccff}\n.hero-shield{filter:drop-shadow(0 0 18px #1bc6ff60) drop-shadow(0 18px 18px #00143270)}\n.hero .hero-shield path.outer{fill:#073261;stroke:#6bcfff;stroke-width:2}\n.hero .hero-shield path.inner{fill:#0c5c99;stroke:#3cbbff;stroke-width:2}\n.hero .hero-shield path.check{stroke:#d8faff;filter:drop-shadow(0 0 5px #54ddff)}\n.stat{background:linear-gradient(145deg,var(--raised),var(--panel));box-shadow:inset 0 1px #a8cfff08}\n.stat .stat-icon{color:var(--mint)}\n.side-menu button.active{box-shadow:inset 3px 0 #4dbbff}\n.bottom-nav button.active{color:var(--mint)}\nbutton,input{transition:background .18s,border-color .18s,box-shadow .18s,transform .18s}\nbutton:active{transform:translateY(1px)}\n[data-theme=light] .hero{box-shadow:0 16px 35px #1764b726}\n[data-theme=light] .stat{background:linear-gradient(145deg,#ffffff,#f4f8ff)}\n[data-theme=light] .brand-mark{color:#8ce0ff}\n@media(prefers-reduced-motion:reduce){button,input{transition:none}}\n\n\n/* Sculpted blue materials and tactile controls */\n:root{--surface-top:#1b3150;--surface-bottom:#101e34;--edge-light:#8fbfff28;--depth:0 10px 24px #01081755,inset 0 1px 0 #a9d7ff14;--control-top:#254a70;--control-bottom:#15314e}\n[data-theme=light]{--surface-top:#ffffff;--surface-bottom:#ecf3ff;--edge-light:#ffffff;--depth:0 8px 22px #244d8620,inset 0 1px 0 #fff;--control-top:#fff;--control-bottom:#e2edff}\n.panel,.stat,.report-stat,.profile-panel,.settings-group{background:linear-gradient(150deg,var(--surface-top),var(--surface-bottom));border-color:var(--edge-light);box-shadow:var(--depth)}\n.stat{border-radius:20px;padding-top:19px}.stat .value{font-weight:750;text-shadow:0 2px 8px #0002}\n.hero{border-radius:28px;background:radial-gradient(ellipse at 100% 0%,#37c7ff70,transparent 54%),radial-gradient(ellipse at 0% 100%,#304fbe60,transparent 70%),linear-gradient(130deg,#123a71,#075e96);box-shadow:inset 0 2px 1px #b4eaff35,inset 0 -3px 10px #00153145,0 20px 40px #00193960;border:1px solid #6bcaff70}\n.hero:before{border-width:2px;box-shadow:0 0 38px #56caff12,inset 0 0 30px #5ccaff08}.hero h2{letter-spacing:-.8px;text-shadow:0 2px 14px #00193755}.hero-shield{filter:drop-shadow(0 3px 1px #001c47) drop-shadow(0 12px 12px #00112b80) drop-shadow(0 0 16px #3acbff60)}\n.hero-link{padding:10px 14px;margin-top:16px;border:1px solid #a8dfff50;border-radius:12px;background:linear-gradient(180deg,#c5efff20,#72bcff0a);box-shadow:inset 0 1px #e9faff35,0 5px 12px #001a3b30;backdrop-filter:blur(8px)}\n.button.primary{background:linear-gradient(175deg,#4dc9ff 0%,#2194ed 48%,#1572d3 100%);color:#fff;border:1px solid #80d9ff80;text-shadow:0 1px 2px #03448480;box-shadow:inset 0 2px 1px #d4f3ff55,inset 0 -2px 1px #034ea860,0 5px 0 #0a3e7a,0 10px 22px #0475d438;border-radius:15px}\n.button.secondary,.icon-btn,.back-button,.chip{background:linear-gradient(165deg,var(--control-top),var(--control-bottom));border:1px solid var(--edge-light);box-shadow:inset 0 1px #b4dbff20,0 4px 8px #0002}\n.quick-scan{background:radial-gradient(ellipse at 0% 0%,#278ffb20,transparent 70%),linear-gradient(145deg,var(--surface-top),var(--surface-bottom));border:1px solid #518fc94a;box-shadow:var(--depth);padding:21px 18px}\n.square-icon{background:linear-gradient(145deg,#287aa5,#123b65);color:#9aeaff;border:1px solid #6bc9ff45;box-shadow:inset 0 2px 2px #cff5ff25,inset 0 -3px 6px #001d3f40,0 6px 10px #0002}\n.square-icon.red{background:linear-gradient(145deg,#683b4b,#3b283c);color:#ffb8b0;border-color:#ffb1aa30}.square-icon.amber{background:linear-gradient(145deg,#725336,#3e342a);color:#ffda97;border-color:#ffd59c30}.square-icon.blue{background:linear-gradient(145deg,#315d91,#20364f);color:#c4dfff}\n.event-row,.chat-row{border-radius:14px;transition:background .2s,transform .2s}.event-row:hover,.chat-row:hover{background:#4f9ce612;transform:translateX(2px)}\n.segmented,.filters{background:var(--bg);box-shadow:inset 0 2px 5px #0003}.segmented button.active,.chip.active{background:linear-gradient(165deg,var(--control-top),var(--control-bottom));color:var(--mint);border-color:#61b9ff45;box-shadow:inset 0 1px #c1e6ff25,0 3px 7px #0003}\n.switch{box-shadow:inset 0 2px 5px #0006;border:1px solid #91c6ff20}.switch.on{background:linear-gradient(180deg,#4ecaff,#087bd9);box-shadow:inset 0 1px 3px #00528d,0 0 12px #159de928}.switch:after,.switch.on:after{background:linear-gradient(#fff,#c6e2f4);box-shadow:0 2px 3px #001a4d60}\n.bottom-nav{background:linear-gradient(180deg,#16283eec,#0b172aed);backdrop-filter:blur(24px);box-shadow:0 -10px 35px #030a1928,inset 0 1px #91bdff20}\n.bottom-nav button{margin:7px 2px;border-radius:15px;transition:all .2s}.bottom-nav button.active{background:linear-gradient(160deg,#2676aa60,#16375650);box-shadow:inset 0 1px #9cdbff30,0 3px 10px #0002;color:#9cdeff}.bottom-nav button.active svg{filter:drop-shadow(0 0 5px #46bdff70)}\nbutton{transition:transform .16s,box-shadow .16s,filter .16s}button:active{transform:translateY(2px) scale(.985)}.button.primary:active{box-shadow:inset 0 2px 5px #00518f60,0 2px 0 #0a3e7a;transform:translateY(3px)}\n@media(hover:hover){.button:hover,.hero-link:hover,.icon-btn:hover{filter:brightness(1.12);transform:translateY(-1px)}}\n[data-theme=light] .bottom-nav{background:linear-gradient(180deg,#ffffffef,#e8f1ffef);box-shadow:0 -8px 30px #1d4a8318,inset 0 1px #fff}\n[data-theme=light] .bottom-nav button.active{background:linear-gradient(150deg,#d5edff,#bbdcff);color:#125cb0;box-shadow:inset 0 1px #fff,0 3px 8px #3569ab20}\n[data-theme=light] .square-icon{background:linear-gradient(145deg,#eaf8ff,#c5e7ff);color:#156ba4;border-color:#fff;box-shadow:inset 0 1px #fff,0 4px 8px #195f9620}\n[data-theme=light] .square-icon.red{background:linear-gradient(145deg,#fff1ed,#f9d9d5);color:#ad463b}[data-theme=light] .square-icon.amber{background:linear-gradient(145deg,#fff8e9,#f6e4c1);color:#8e601c}\n@media(prefers-reduced-motion:reduce){button,.event-row,.chat-row{transition:none}}\n\n\n/* Precision duotone event icons */\n.sculpted-icon .icon-volume{fill:currentColor;fill-opacity:.15;stroke:currentColor;stroke-opacity:.25;transform:translate(0,1px)}\n.sculpted-icon .icon-face{fill:currentColor;fill-opacity:.13;stroke:currentColor;stroke-width:1.5}\n.sculpted-icon .icon-fold{fill:currentColor;fill-opacity:.3;stroke:currentColor;stroke-width:1.4}\n.sculpted-icon .icon-detail{fill:none;stroke:currentColor;stroke-width:1.8}\n.sculpted-icon .icon-glint{fill:none;stroke:#fff;stroke-opacity:.55;stroke-width:1}\n.square-icon{position:relative;isolation:isolate;overflow:hidden;border-radius:15px;background:radial-gradient(ellipse at 22% 0%,#7cd9ff55,transparent 65%),linear-gradient(145deg,#235584,#102849);border:1px solid #a4dfff50;box-shadow:inset 0 1px 1px #d8f5ff70,inset 0 -3px 6px #00132d80,0 5px 0 #06142680,0 8px 15px #0003;color:#b6edff}\n.square-icon:before{content:"";position:absolute;inset:1px 2px auto;height:43%;border-radius:12px 12px 45% 45%;background:linear-gradient(180deg,#ffffff25,#ffffff00);z-index:-1}\n.square-icon svg{width:27px;height:27px;filter:drop-shadow(0 2px 1px #00122e80) drop-shadow(0 0 5px #6fcfff35)}\n.square-icon.red{background:radial-gradient(ellipse at 20% 0%,#ffbbbd50,transparent 65%),linear-gradient(145deg,#854e69,#38273d);color:#ffd3d6;border-color:#ffc6d150}\n.square-icon.amber{background:radial-gradient(ellipse at 20% 0%,#ffe1a950,transparent 65%),linear-gradient(145deg,#8b6943,#3f3028);color:#ffe0a5;border-color:#ffe5b050}\n.square-icon.blue{background:radial-gradient(ellipse at 20% 0%,#9dd3ff50,transparent 65%),linear-gradient(145deg,#386ea4,#183754);color:#d2edff;border-color:#c4e8ff50}\n[data-theme=light] .square-icon{box-shadow:inset 0 1px #fff,inset 0 -2px 3px #6f9dbe25,0 3px 0 #a8c8e040,0 6px 12px #235a8a20}\n[data-theme=light] .square-icon svg{filter:drop-shadow(0 1px 0 #fff)}\n\n\n.live-app{max-width:700px;margin:auto;padding:22px 20px 110px}.live-head{display:flex;align-items:center;gap:12px;margin-bottom:28px}.live-head button{margin-left:auto}.live-app .content{padding:0}.live-app .quick-scan{margin:14px 0}.section-title{font-size:20px;margin:28px 0 12px}.live-shield{position:absolute;right:20px;top:85px;font-size:80px;filter:drop-shadow(0 8px 15px #0007)}.live-app .hero h2{max-width:75%}.bottom-nav{display:flex!important;position:fixed;bottom:0;left:0;right:0;justify-content:center;min-height:78px;padding-bottom:env(safe-area-inset-bottom)}.bottom-nav button{flex:1;max-width:150px;font-size:12px;padding:16px 4px}.setting-row{gap:16px;min-height:85px}#notice{color:var(--amber);font-size:14px;margin:12px 0}.live-head strong{font-size:21px}\n</style></head><body><div class="live-app"><header class="live-head"><span class="brand-mark">🛡</span><div><strong>Qalqon AI</strong><div id="who" class="muted tiny"></div></div><button id="theme" class="icon-btn" aria-label="Rang rejimi">◐</button></header><div id="notice" role="status"></div><main id="content" class="content"><p>Yuklanmoqda…</p></main></div><nav class="bottom-nav"><button data-nav="home">🛡<br>Bosh sahifa</button><button data-nav="messages">▤<br>Xabarlar</button><button data-nav="reports">▥<br>Hisobot</button><button data-nav="settings">⚙<br>Sozlamalar</button></nav><script>\nconst tg=window.Telegram?.WebApp; tg?.ready(); tg?.expand();\nlet data=null,page=\'home\',busy=false;\nconst labels={autoDelete:\'Avto o‘chirish\',outgoing:\'Yuborilgan xabar ogohlantirishi\',history:\'O‘chirilgan xabarlar tarixi\'};\nconst esc=s=>String(s??\'\').replace(/[&<>"\']/g,c=>({\'&\':\'&amp;\',\'<\':\'&lt;\',\'>\':\'&gt;\',\'"\':\'&quot;\',"\'":\'&#39;\'}[c]));\nasync function api(action=\'state\',extra={}){const r=await fetch(\'/miniapp/api\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({initData:tg?.initData||\'\',action,...extra})});const x=await r.json();if(!r.ok)throw Error(x.error||\'Qayta urinib ko‘ring\');return x}\nfunction notice(t){document.getElementById(\'notice\').textContent=t}\nfunction render(){if(!data)return;document.getElementById(\'who\').textContent=data.name;let body=\'\';\nif(page===\'home\')body=`<section class="hero"><div class="hero-status">${data.connected?\'Business ulangan\':\'Business ulanmagan\'}</div><h2>Himoyangiz<br>nazorat ostida.</h2><p>Telegram xavfsizligini bir joydan boshqaring.</p><button class="hero-link" data-nav="settings">Himoyani boshqarish →</button><div class="live-shield">🛡</div></section><div class="stats"><div class="stat"><div class="value">${data.events.length}</div><div class="tiny muted">7 kunlik hodisalar</div></div><div class="stat"><div class="value">${Object.values(data.settings).filter(Boolean).length}</div><div class="tiny muted">Yoqilgan rejimlar</div></div><div class="stat"><div class="value">72 soat</div><div class="tiny muted">Tarix muddati</div></div></div><h2 class="section-title">Tezkor amallar</h2><button class="quick-scan" data-action="apk">🔬 APK tekshirish · 100 MB <span class="push">→</span></button><button class="quick-scan" data-nav="messages">📝 O‘chirilgan xabarlar <span class="push">→</span></button><p class="muted small">Faqat siz tanlagan Telegram Business chatlari kuzatiladi.</p>`;\nif(page===\'settings\')body=`<h1>Himoya sozlamalari</h1><p class="muted">Rejimlarni o‘zingiz boshqaring.</p><div class="panel">${Object.entries(labels).map(([k,v])=>`<div class="setting-row"><span>${v}</span><button role="switch" aria-label="${v}" aria-checked="${data.settings[k]}" class="switch ${data.settings[k]?\'on\':\'\'}" data-setting="${k}"></button></div>`).join(\'\')}</div><p class="muted small">Tarix yoqilsa, xabar matnlari va media identifikatorlari 72 soatgacha saqlanadi. Avto o‘chirish barcha havolali xabarlarni ham o‘chiradi.</p><button class="button secondary full" data-action="connection">Ulanish va ruxsatlarni tekshirish</button>`;\nif(page===\'messages\')body=`<h1>O‘chirilgan xabarlar</h1><div class="panel"><h2>${data.settings.history?\'Tarix yoqilgan\':\'Tarix o‘chirilgan\'}</h2><p class="muted">Chatni tanlash va saqlangan xabarlarni olish uchun botda tarix bo‘limini oching.</p><button class="button primary full" data-action="history">Botda xabarlarni ko‘rish →</button></div>`;\nif(page===\'reports\')body=`<h1>So‘nggi 7 kun</h1><p class="muted">Shaxsiy xavfsizlik hodisalaringiz</p><div class="panel">${data.events.length?data.events.map(e=>`<div class="event-row"><div class="square-icon ${e.category.includes(\'apk\')?\'red\':\'blue\'}">${e.category.includes(\'apk\')?\'▤\':\'🛡\'}</div><div><h3>${esc(e.chat)}</h3><p class="tiny muted">${esc(e.category)} · ${esc(e.action)}</p><p class="tiny muted">${esc(new Date(e.time*1000).toLocaleString(\'uz-UZ\'))}</p></div></div>`).join(\'\'):\'Hozircha qayd etilgan hodisalar yo‘q.\'}</div>`;\ndocument.getElementById(\'content\').innerHTML=body;document.querySelectorAll(\'[data-nav]\').forEach(b=>b.classList.toggle(\'active\',b.dataset.nav===page));}\ndocument.addEventListener(\'click\',async e=>{const b=e.target.closest(\'button\');if(!b||busy)return;if(b.dataset.nav){page=b.dataset.nav;render();return}if(b.id===\'theme\'){document.documentElement.dataset.theme=document.documentElement.dataset.theme===\'light\'?\'dark\':\'light\';return}try{busy=true;b.disabled=true;if(b.dataset.setting){const k=b.dataset.setting,on=!data.settings[k];if(on&&!confirm(k===\'autoDelete\'?\'APK va barcha havolali xabarlarni avtomatik o‘chirish yoqilsinmi?\':k===\'history\'?\'Xabar matnlari va media identifikatorlarini 72 soatgacha saqlashga rozimisiz?\':\'Siz yuborgan shubhali APK va havolalar ostida ogohlantirish yozilsinmi?\'))return;data=await api(\'setting\',{key:k,enabled:on});render()}else if(b.dataset.action){await api(b.dataset.action);notice(\'Botga yuborildi. Telegram chatiga qayting.\');tg?.close()}}catch(e){notice(e.message)}finally{busy=false;b.disabled=false}});\napi().then(x=>{data=x;render()}).catch(e=>notice(e.message));\n</script></body></html>'


def miniapp_identity(raw: str) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw or len(raw) > 12000:
        raise ValueError("Ilovani Telegram botidagi tugmadan oching")
    pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=True)
    values = dict(pairs)
    if len(pairs) != len(values):
        raise ValueError("Invalid authentication")
    supplied = values.pop("hash", "")
    check = "\n".join(f"{k}={v}" for k, v in sorted(values.items()))
    key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    expected = hmac.new(key, check.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        raise ValueError("Telegram tasdig‘i noto‘g‘ri")
    age = time.time() - int(values.get("auth_date", "0"))
    if not -30 <= age <= 3600:
        raise ValueError("Ilovani yoping va botdan qayta oching")
    user = json.loads(values.get("user", "{}"))
    if not isinstance(user.get("id"), int) or user["id"] <= 0:
        raise ValueError("Invalid user")
    return user


def register_miniapp(app, session, store):
    limiter = {}
    async def page(request):
        return web.Response(text=MINIAPP_HTML, content_type="text/html", headers={
            "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline' https://telegram.org; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors https://web.telegram.org https://*.telegram.org; base-uri 'none'; form-action 'none'",
        })
    async def endpoint(request):
        try:
            if request.content_type != 'application/json':
                return web.json_response({'error': 'JSON required'}, status=415)
            payload = await request.json()
            user = miniapp_identity(payload.get('initData', ''))
        except (ValueError, TypeError, AttributeError):
            return web.json_response({'error': 'Ilovani Telegram botidagi tugmadan qayta oching'}, status=401)
        owner = user['id']
        now = time.monotonic()
        if now - limiter.get(owner, 0) < .5:
            return web.json_response({'error': 'Bir oz kutib qayta bosing'}, status=429)
        if len(limiter) > 10000:
            limiter.clear()
        limiter[owner] = now
        if await subscription_state(session, owner) != 'member':
            await send_subscription_prompt(session, owner, await subscription_state(session, owner))
            return web.json_response({'error': 'Avval botdagi kanal obunasini tasdiqlang'}, status=403)
        action = payload.get('action', 'state')
        try:
            if action == 'setting':
                key, enabled = payload.get('key'), payload.get('enabled')
                if key not in ('autoDelete', 'outgoing', 'history') or type(enabled) is not bool:
                    return web.json_response({'error': 'Invalid setting'}, status=400)
                setters = {'autoDelete': store.set_auto_delete, 'outgoing': store.set_outgoing_warning, 'history': store.set_history}
                setters[key](owner, enabled)
            elif action == 'history':
                await send_history_menu(session, store, owner)
            elif action == 'apk':
                await offer_large_apk_upload(session, owner)
            elif action == 'connection':
                await send_security_center(session, store, owner)
            elif action != 'state':
                return web.json_response({'error': 'Unknown action'}, status=400)
            events = store.security_events(owner, time.time() - 7 * 86400)
            return web.json_response({'name': user.get('first_name', ''), 'connected': bool(store.active_connection_id(owner)),
                'settings': {'autoDelete': store.auto_delete_enabled(owner), 'outgoing': store.outgoing_warning_enabled(owner), 'history': store.history_enabled(owner)},
                'events': [{'chat': row[1], 'category': row[2], 'action': row[3], 'time': row[5]} for row in events[:100]]})
        except (TelegramAPIError, sqlite3.Error):
            return web.json_response({'error': 'Xizmat vaqtincha band. Qayta urinib ko‘ring.'}, status=503)
    app.router.add_get('/miniapp', page)
    app.router.add_post('/miniapp/api', endpoint)


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
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        response.headers["Strict-Transport-Security"] = "max-age=31536000"

    app = web.Application(client_max_size=MAX_WEBHOOK_BYTES)
    app.on_response_prepare.append(secure_response)
    app.router.add_get("/", health)
    app.router.add_get("/healthz", health)
    register_miniapp(app, session, store)
    app.router.add_post(WEBHOOK_PATH, webhook)
    APK_UPLOAD_SERVICE.register(
        app,
        lambda owner, name, source: run_uploaded_apk_inspection(session, owner, name, source),
        APK_SCAN_JOBS,
        lambda owner: APK_SCAN_LIMITER.allow(("apk", owner)),
        access_owner=lambda owner: subscription_upload_allowed(session, owner),
    )
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
    async def expire_history() -> None:
        while True:
            await asyncio.sleep(60)
            try:
                DELETED_HISTORY.prune()
            except TelegramTemporaryError:
                log.warning("Tarix bazasini tozalash vaqtincha kechiktirildi")
    expiry_task = asyncio.create_task(expire_history())
    try:
        await asyncio.Event().wait()
    finally:
        expiry_task.cancel()
        await asyncio.gather(expiry_task, return_exceptions=True)
        await runner.cleanup()


async def run() -> None:
    global DELETED_HISTORY
    history_url = os.environ.get("HISTORY_DATABASE_URL", "").strip()
    if history_url:
        try:
            DELETED_HISTORY = PostgresMessageHistory(history_url)
            log.info("History storage: PostgreSQL connected; schema and cleanup verified")
        except TelegramTemporaryError:
            DELETED_HISTORY = TemporaryMessageHistory()
            log.error("History storage: PostgreSQL unavailable at startup; bot continues in RAM-only mode")
    else:
        log.warning("History storage: RAM only; HISTORY_DATABASE_URL is not configured")
    if not re.fullmatch(r"[0-9]{6,}:[A-Za-z0-9_-]{20,}", BOT_TOKEN):
        raise SystemExit("BOT_TOKEN topilmadi yoki formati noto‘g‘ri. Render maxfiy sozlamasini tekshiring.")
    store = Store(DB_PATH)
    timeout = aiohttp.ClientTimeout(total=40, connect=15)
    connector = aiohttp.TCPConnector(limit=10, ttl_dns_cache=300)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        me = await api(session, "getMe")
        log.info("Bot ishga tushdi: @%s", me.get("username", "unknown"))
        SUBSCRIPTION_GATE.bot_id = int(me["id"])
        if SUBSCRIPTION_GATE.channel:
            ready = await SUBSCRIPTION_GATE.admin_ready(lambda method, payload: api(session, method, payload), force=True)
            log.info("Required channel subscription: %s; admin verification %s", SUBSCRIPTION_GATE.channel, "ready" if ready else "unavailable (add bot as channel administrator)")
        try:
            await api(session, "deleteMyCommands")
        except TelegramAPIError as exc:
            if isinstance(exc, TelegramTemporaryError):
                raise
            log.warning("Bot menyusidagi eski buyruqlarni tozalash imkoni bo‘lmadi: %s", exc)
        miniapp_origin = os.environ.get("RENDER_EXTERNAL_URL", "").rstrip("/")
        if miniapp_origin:
            miniapp_url = miniapp_origin + "/miniapp"
            MAIN_KEYBOARD["keyboard"].insert(0, [{"text": "🛡 Ilovani ochish", "web_app": {"url": miniapp_url}}])
            try:
                await api(session, "setChatMenuButton", {"menu_button": {"type": "web_app", "text": "🛡 Qalqon AI", "web_app": {"url": miniapp_url}}})
            except TelegramAPIError:
                log.warning("Mini App menyusini sozlash vaqtincha bajarilmadi")
        reputation_task = asyncio.create_task(THREAT_INTEL.run(session))
        try:
            if os.environ.get("RENDER_EXTERNAL_URL"):
                await run_webhook(session, store)
            else:
                await run_polling(session, store)
        finally:
            reputation_task.cancel()
            jobs = list(APK_SCAN_JOBS)
            for job in jobs:
                job.cancel()
            await asyncio.gather(reputation_task, *jobs, return_exceptions=True)


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        log.info("Bot to‘xtatildi")

