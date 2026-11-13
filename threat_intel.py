"""Bounded reputation lookups and passive APK inspection. Never execute samples."""
from __future__ import annotations

import asyncio
from collections import OrderedDict
import hashlib
import io
import json
import logging
from pathlib import Path
import re
import struct
import time
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
import zipfile

import aiohttp

log = logging.getLogger("telegram_himoya")
FEED_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"
MAX_APK_BYTES = 20 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
SHARED_HOSTS = {"t.me", "telegram.org", "telegram.me", "github.com", "raw.githubusercontent.com",
                "drive.google.com", "docs.google.com", "youtube.com", "www.youtube.com"}
RISK_PERMISSIONS = {
    "android.permission.READ_SMS": "SMS xabarlarini o‘qish",
    "android.permission.RECEIVE_SMS": "Kelgan SMS’larni qabul qilish",
    "android.permission.SEND_SMS": "SMS yuborish",
    "android.permission.READ_CONTACTS": "Kontaktlarni o‘qish",
    "android.permission.RECORD_AUDIO": "Mikrofon yozuvi",
    "android.permission.SYSTEM_ALERT_WINDOW": "Boshqa ilovalar ustida oyna ko‘rsatish",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Boshqa ilovalarni o‘rnatishni so‘rash",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "Barcha fayllarga kirish",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Maxsus imkoniyatlar xizmati",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "Bildirishnomalarni o‘qish xizmati",
}


def canonical_host(value: str) -> str:
    try:
        value = value.strip().rstrip(".").lower().encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if len(value) > 253 or "." not in value:
        return ""
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split(".")):
        return ""
    return value


class DomainReputation:
    """Exact host matches only; do not condemn parent domains or shared platforms."""
    def __init__(self, cache_path: Path):
        self.cache_path = cache_path
        self.hosts: set[str] = set()
        self.updated_at = 0.0

    @staticmethod
    def parse(data: bytes) -> set[str]:
        hosts = set()
        for line in data.decode("utf-8").splitlines():
            if not line or line.startswith(("#", "!")):
                continue
            host = canonical_host(line)
            if host and host not in SHARED_HOSTS:
                hosts.add(host)
            if len(hosts) > 750000:
                raise ValueError("Feed too large")
        if len(hosts) < 100:
            raise ValueError("Feed is incomplete")
        return hosts

    def load_cache(self):
        try:
            stat = self.cache_path.stat()
            if stat.st_size > 24 * 1024 * 1024 or time.time() - stat.st_mtime > 7 * 86400:
                return
            hosts = self.parse(self.cache_path.read_bytes())
            self.hosts, self.updated_at = hosts, stat.st_mtime
        except (OSError, ValueError, UnicodeError):
            pass

    def matches(self, host: str) -> bool:
        return time.time() - self.updated_at <= 7 * 86400 and canonical_host(host) in self.hosts

    def status(self) -> str:
        if not self.hosts or time.time() - self.updated_at > 7 * 86400:
            return "⚪ bazaga hali ulanmagan"
        freshness = "🟢 yangilangan" if time.time() - self.updated_at <= 86400 else "⚠️ yangilanish kechikkan"
        return f"{freshness} · {len(self.hosts):,} domen"

    def save_cache(self, data: bytes):
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        pending = self.cache_path.with_suffix(".tmp")
        pending.write_bytes(data)
        pending.replace(self.cache_path)

    async def refresh(self, session):
        async with session.get(FEED_URL, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=60)) as response:
            if response.status != 200:
                raise ValueError("Feed unavailable")
            data = bytearray()
            async for chunk in response.content.iter_chunked(65536):
                data.extend(chunk)
                if len(data) > 24 * 1024 * 1024:
                    raise ValueError("Feed too large")
        hosts = await asyncio.to_thread(self.parse, bytes(data))
        self.hosts, self.updated_at = hosts, time.time()
        try:
            await asyncio.to_thread(self.save_cache, bytes(data))
        except OSError:
            log.warning("Phishing feed cache could not be saved")
        log.info("Threat intelligence: Phishing.Database loaded (%s domains)", len(hosts))

    async def run(self, session):
        await asyncio.to_thread(self.load_cache)
        while True:
            try:
                await self.refresh(session)
                delay = 6 * 3600
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, UnicodeError, OSError):
                log.warning("Threat intelligence: refresh unavailable; retaining last usable feed")
                delay = 900
            await asyncio.sleep(delay)


def manifest_permissions(data: bytes) -> set[str]:
    """Read uses-permission and service-permission values from plain XML or AXML."""
    if len(data) > MAX_MANIFEST_BYTES:
        raise ValueError("Manifest too large")
    if data.lstrip().startswith(b"<"):
        if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
            raise ValueError("Unsupported XML declarations")
        root = ET.fromstring(data)
        permissions = set()
        for node in root.iter():
            tag = node.tag.rsplit("}", 1)[-1]
            if tag.startswith("uses-permission"):
                permissions.add(node.attrib.get("{http://schemas.android.com/apk/res/android}name", ""))
            if tag == "service":
                permissions.add(node.attrib.get("{http://schemas.android.com/apk/res/android}permission", ""))
        return permissions - {""}
    if len(data) < 8 or struct.unpack_from("<H", data)[0] != 3:
        raise ValueError("Unsupported Android manifest")
    _, header, total = struct.unpack_from("<HHI", data)
    if not 8 <= header <= total <= len(data):
        raise ValueError("Invalid AXML header")
    strings: list[str] = []
    permissions = set()
    offset, chunks = header, 0
    while offset < total:
        chunks += 1
        if chunks > 30000 or offset + 8 > total:
            raise ValueError("Invalid AXML chunk")
        kind, head, size = struct.unpack_from("<HHI", data, offset)
        end = offset + size
        if head < 8 or size < head or end > total:
            raise ValueError("Invalid AXML bounds")
        if kind == 1:
            if head < 28:
                raise ValueError("Invalid string pool")
            count, _, flags, start, _ = struct.unpack_from("<IIIII", data, offset + 8)
            if count > 30000 or head + count * 4 > size or not head + count * 4 <= start <= size:
                raise ValueError("Invalid string offsets")
            strings = []
            def length(pos, utf8):
                width = 1 if utf8 else 2
                if pos + width > end:
                    raise ValueError("Invalid string length")
                value = data[pos] if utf8 else struct.unpack_from("<H", data, pos)[0]
                pos += width
                flag = 0x80 if utf8 else 0x8000
                if value & flag:
                    if pos + width > end:
                        raise ValueError("Invalid extended string length")
                    extra = data[pos] if utf8 else struct.unpack_from("<H", data, pos)[0]
                    value = ((value & (flag - 1)) << (8 if utf8 else 16)) | extra
                    pos += width
                return value, pos
            for index in range(count):
                relative = struct.unpack_from("<I", data, offset + head + index * 4)[0]
                pos = offset + start + relative
                utf8 = bool(flags & 0x100)
                if utf8:
                    _, pos = length(pos, True)
                n, pos = length(pos, utf8)
                n *= 1 if utf8 else 2
                if n > 8192 or pos + n > end:
                    raise ValueError("Invalid string body")
                strings.append(data[pos:pos + n].decode("utf-8" if utf8 else "utf-16-le"))
        elif kind == 0x102:
            if head < 16 or size < 36:
                raise ValueError("Invalid start element")
            name_index = struct.unpack_from("<I", data, offset + 20)[0]
            attr_start, attr_size, count = struct.unpack_from("<HHH", data, offset + 24)
            pos = offset + 16 + attr_start
            if attr_size < 20 or pos < offset + 36 or pos + count * attr_size > end:
                raise ValueError("Invalid attributes")
            tag = strings[name_index] if name_index < len(strings) else ""
            for index in range(count):
                base = pos + index * attr_size
                namespace, key, raw = struct.unpack_from("<III", data, base)
                value_type = data[base + 15]
                value_index = struct.unpack_from("<I", data, base + 16)[0]
                key_name = strings[key] if key < len(strings) else ""
                android_namespace = namespace < len(strings) and strings[namespace] == "http://schemas.android.com/apk/res/android"
                value = strings[raw] if raw < len(strings) else strings[value_index] if value_type == 3 and value_index < len(strings) else ""
                if android_namespace and ((tag in {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"} and key_name == "name") or (tag == "service" and key_name == "permission")):
                    if value:
                        permissions.add(value)
        offset = end
    return permissions


def inspect_apk(data: bytes) -> dict:
    if len(data) > MAX_APK_BYTES:
        raise ValueError("APK too large")
    result = {"sha256": hashlib.sha256(data).hexdigest(), "permissions": [], "valid_apk": False, "manifest_read": False}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if len(archive.infolist()) > 10000:
                raise ValueError("Too many APK entries")
            info = archive.getinfo("AndroidManifest.xml")
            if info.file_size > MAX_MANIFEST_BYTES or info.flag_bits & 1:
                raise ValueError("Manifest unavailable")
            with archive.open(info) as manifest:
                body = manifest.read(MAX_MANIFEST_BYTES + 1)
            permissions = manifest_permissions(body)
            result.update(valid_apk=True, manifest_read=True, permissions=sorted(permissions & RISK_PERMISSIONS.keys()))
    except (zipfile.BadZipFile, KeyError, ValueError, UnicodeError, ET.ParseError, struct.error, RuntimeError, NotImplementedError):
        pass
    return result


class HashReputation:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key.strip()
        self.cache = OrderedDict()
        self.last_request = 0.0
        self.lock = asyncio.Lock()

    async def lookup(self, session, sha256: str) -> dict:
        if not re.fullmatch(r"[a-f0-9]{64}", sha256):
            raise ValueError("Invalid SHA256")
        if not self.api_key:
            return {"status": "disabled"}
        cached = self.cache.get(sha256)
        if cached and time.monotonic() - cached[0] < 3600:
            return cached[1]
        async with self.lock:
            if time.monotonic() - self.last_request < 16:
                return {"status": "rate_limited"}
            self.last_request = time.monotonic()
            try:
                async with session.get(
                    f"https://www.virustotal.com/api/v3/files/{sha256}",
                    headers={"x-apikey": self.api_key}, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=12),
                ) as response:
                    if response.status == 404:
                        return {"status": "not_found"}
                    if response.status == 429:
                        return {"status": "rate_limited"}
                    if response.status != 200:
                        return {"status": "unavailable"}
                    raw = bytearray()
                    async for chunk in response.content.iter_chunked(65536):
                        raw.extend(chunk)
                        if len(raw) > 1024 * 1024:
                            return {"status": "unavailable"}
                    body = json.loads(raw)
                    stats = body["data"]["attributes"]["last_analysis_stats"]
                    result = {"status": "found", "malicious": max(0, int(stats.get("malicious", 0))),
                              "suspicious": max(0, int(stats.get("suspicious", 0))),
                              "undetected": max(0, int(stats.get("undetected", 0)))}
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, KeyError, TypeError):
                return {"status": "unavailable"}
            self.cache[sha256] = (time.monotonic(), result)
            while len(self.cache) > 128:
                self.cache.popitem(last=False)
            return result
