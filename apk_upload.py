"""Single-use, owner-routed uploads for APKs larger than Telegram getFile permits."""
from __future__ import annotations

import asyncio
from collections import OrderedDict
from pathlib import Path
import re
import secrets
import tempfile
import time

from aiohttp import web

from threat_intel import MAX_UPLOAD_BYTES


class ApkUploadService:
    def __init__(self, origin: str):
        self.origin = origin.rstrip("/")
        self.tokens = OrderedDict()
        self.active_uploads = 0

    def issue(self, owner: int, name: str = "yuklangan.apk") -> str:
        now = time.monotonic()
        for token in [key for key, value in self.tokens.items() if value["expires"] <= now or value["owner"] == owner]:
            del self.tokens[token]
        token = secrets.token_urlsafe(32)
        self.tokens[token] = {"owner": owner, "name": name[:128], "expires": now + 900}
        while len(self.tokens) > 100:
            self.tokens.popitem(last=False)
        return token

    def valid(self, token):
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return None
        item = self.tokens.get(token)
        return item if item and item["expires"] > time.monotonic() else None

    def register(self, app, on_scan, jobs, allow_owner):
        async def page(request):
            token = request.match_info["token"]
            if not self.valid(token):
                raise web.HTTPGone(text="Havola eskirgan. Botdan yangi tekshiruv havolasini oling.")
            nonce = secrets.token_urlsafe(24)
            template = Path(__file__).with_name("apk_upload.html").read_text(encoding="utf-8")
            return web.Response(
                text=template.replace("__TOKEN__", token).replace("__NONCE__", nonce),
                content_type="text/html",
                headers={
                    "Content-Security-Policy": f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors https://web.telegram.org https://webk.telegram.org https://webz.telegram.org",
                    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                },
            )

        async def close_after_scan(source, item):
            try:
                await on_scan(item["owner"], item["name"], source)
            finally:
                source.close()

        async def upload(request):
            token = request.match_info["token"]
            item = self.valid(token)
            headers = request.headers.getall("X-Upload-Token", [])
            header = headers[0] if len(headers) == 1 else ""
            if not item or not secrets.compare_digest(header, token):
                raise web.HTTPForbidden(text="Tekshiruv havolasi yaroqsiz yoki ishlatilgan.")
            if request.headers.getall("Origin", []) != [self.origin]:
                raise web.HTTPForbidden(text="So‘rov manbasi noto‘g‘ri.")
            if request.content_type != "application/octet-stream" or request.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise web.HTTPUnsupportedMediaType()
            if request.headers.get("X-Scan-Consent") != "yes":
                raise web.HTTPForbidden(text="Tekshirishga rozilik talab qilinadi.")
            if request.content_length is not None and request.content_length > MAX_UPLOAD_BYTES:
                raise web.HTTPRequestEntityTooLarge(max_size=MAX_UPLOAD_BYTES, actual_size=request.content_length)
            if self.active_uploads >= 2 or self.active_uploads + len(jobs) >= 3 or not allow_owner(item["owner"]):
                raise web.HTTPTooManyRequests(text="Tekshiruv band yoki soatlik limit tugagan. Keyinroq urinib ko‘ring.")
            # Claim before the first await: a link can start at most one upload.
            self.tokens.pop(token)
            self.active_uploads += 1
            source = None
            handed_off = False
            try:
                source = tempfile.TemporaryFile(mode="w+b")
                async def receive():
                    total = 0
                    while True:
                        chunk = await asyncio.wait_for(request.content.read(65536), timeout=30)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > MAX_UPLOAD_BYTES:
                            raise web.HTTPRequestEntityTooLarge(max_size=MAX_UPLOAD_BYTES, actual_size=total)
                        source.write(chunk)
                    if not total:
                        raise web.HTTPBadRequest(text="Bo‘sh fayl yuborilgan.")
                await asyncio.wait_for(receive(), timeout=300)
                task = asyncio.create_task(close_after_scan(source, item))
                jobs.add(task)
                task.add_done_callback(jobs.discard)
                handed_off = True
                return web.json_response({"ok": True, "message": "Fayl qabul qilindi. Natija Qalqon AI botidagi chattingizga yuboriladi."}, status=202)
            except asyncio.TimeoutError:
                raise web.HTTPRequestTimeout(text="Yuklash vaqti tugadi. Botdan yangi havola olib qayta urinib ko‘ring.") from None
            except OSError:
                raise web.HTTPServiceUnavailable(text="Faylni qabul qilib bo‘lmadi. Keyinroq urinib ko‘ring.") from None
            finally:
                self.active_uploads -= 1
                if source is not None and not handed_off:
                    source.close()

        app.router.add_get("/apk-upload/{token}", page)
        app.router.add_post("/apk-upload/{token}", upload)
