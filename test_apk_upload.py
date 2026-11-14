"""Large APK upload/authentication/cleanup regression tests; no Telegram calls."""
import asyncio
import hashlib
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch
import zipfile

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import apk_upload
from apk_upload import ApkUploadService
import main
from threat_intel import inspect_apk_file, MAX_UPLOAD_BYTES


class LargeApkTests(unittest.TestCase):
    def test_25mb_apk_scans_from_disk_in_bounded_reads(self):
        with tempfile.TemporaryFile("w+b") as source:
            with zipfile.ZipFile(source, "w", zipfile.ZIP_STORED) as archive:
                archive.writestr("AndroidManifest.xml", b'<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-permission android:name="android.permission.READ_SMS"/></manifest>')
                with archive.open("assets/padding.bin", "w") as asset:
                    for _ in range(25 * 16):
                        asset.write(b"\0" * 65536)
            self.assertGreater(source.tell(), 20 * 1024 * 1024)
            result = inspect_apk_file(source)
            self.assertTrue(result["manifest_read"])
            self.assertEqual(result["permissions"], ["android.permission.READ_SMS"])
            source.seek(0)
            digest = hashlib.sha256()
            while chunk := source.read(65536):
                digest.update(chunk)
            self.assertEqual(result["sha256"], digest.hexdigest())

    def test_over_100mb_file_rejected_before_hashing(self):
        with tempfile.TemporaryFile("w+b") as source:
            source.truncate(MAX_UPLOAD_BYTES + 1)
            with self.assertRaises(ValueError):
                inspect_apk_file(source)


class UploadHttpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.service = ApkUploadService("https://bot.example")
        self.jobs = set()
        self.received = asyncio.Event()
        self.results = []
        async def scan(owner, name, source):
            source.seek(0)
            self.results.append((owner, name, source.read(), source))
            self.received.set()
        self.app = web.Application(client_max_size=1024)
        self.service.register(self.app, scan, self.jobs, lambda owner: True)
        self.client = TestClient(TestServer(self.app))
        await self.client.start_server()
        self.token = self.service.issue(123, "test.apk")
        self.path = "/apk-upload/" + self.token
        self.headers = {"X-Upload-Token": self.token, "Origin": "https://bot.example", "Content-Type": "application/octet-stream", "X-Scan-Consent": "yes"}

    async def asyncTearDown(self):
        if self.jobs:
            await asyncio.gather(*list(self.jobs))
        await self.client.close()

    async def test_page_has_nonce_and_explicit_disk_consent(self):
        response = await self.client.get(self.path)
        body = await response.text()
        self.assertEqual(response.status, 200)
        self.assertIn("100 MB", body)
        self.assertIn("vaqtinchalik server fayliga", body)
        self.assertIn("nonce-", response.headers["Content-Security-Policy"])
        self.assertNotIn("__NONCE__", body)
        self.assertNotIn("__TOKEN__", body)

    async def test_upload_stream_bypasses_webhook_limit_and_routes_to_token_owner(self):
        payload = b"harmless fixture" * 40000
        response = await self.client.post(self.path, data=payload, headers=self.headers)
        self.assertEqual(response.status, 202)
        await asyncio.wait_for(self.received.wait(), timeout=2)
        owner, name, data, source = self.results[0]
        self.assertEqual((owner, name), (123, "test.apk"))
        self.assertEqual(data, payload)
        await asyncio.sleep(0)
        self.assertTrue(source.closed)
        repeat = await self.client.post(self.path, data=b"fixture", headers=self.headers)
        self.assertEqual(repeat.status, 403)

    async def test_wrong_token_origin_consent_and_encoding_are_rejected(self):
        cases = [({**self.headers, "X-Upload-Token": "wrong"}, 403),
                 ({**self.headers, "Origin": "https://attacker.example"}, 403),
                 ({key: value for key, value in self.headers.items() if key != "X-Scan-Consent"}, 403),
                 ({**self.headers, "Content-Encoding": "gzip"}, 415)]
        for headers, status in cases:
            response = await self.client.post(self.path, data=b"fixture", headers=headers)
            self.assertEqual(response.status, status)
        self.assertEqual(self.results, [])
        self.assertIn(self.token, self.service.tokens)

    async def test_expired_link_is_not_accepted(self):
        self.service.tokens[self.token]["expires"] = time.monotonic() - 1
        self.assertEqual((await self.client.get(self.path)).status, 410)
        self.assertEqual((await self.client.post(self.path, data=b"fixture", headers=self.headers)).status, 403)

    async def test_chunked_oversize_upload_closes_temporary_file(self):
        created = []
        original = tempfile.TemporaryFile
        def temporary(*args, **kwargs):
            source = original(*args, **kwargs)
            created.append(source)
            return source
        async def chunks():
            yield b"a" * 800
            yield b"b" * 800
        with patch.object(apk_upload, "MAX_UPLOAD_BYTES", 1024), patch.object(apk_upload.tempfile, "TemporaryFile", temporary):
            response = await self.client.post(self.path, data=chunks(), headers=self.headers)
            self.assertEqual(response.status, 413)
        self.assertEqual(len(created), 1)
        self.assertTrue(created[0].closed)
        self.assertEqual(self.service.active_uploads, 0)
        self.assertEqual(self.results, [])

    async def test_repeated_token_header_is_rejected(self):
        headers = list(self.headers.items()) + [("X-Upload-Token", self.token)]
        self.assertEqual((await self.client.post(self.path, data=b"fixture", headers=headers)).status, 403)

    async def test_large_telegram_document_receives_upload_button_without_getfile(self):
        message = {"chat": {"id": 123, "type": "private"}, "document": {"file_id": "fixture", "file_name": "big.apk", "file_size": 50 * 1024 * 1024}}
        with patch.object(main, "APK_UPLOAD_SERVICE", self.service), patch.object(main, "api", AsyncMock()) as api:
            await main.offer_apk_inspection(None, message)
            self.assertEqual(api.await_count, 1)
            self.assertEqual(api.await_args.args[1], "sendMessage")
            markup = api.await_args.args[2]["reply_markup"]["inline_keyboard"][0][0]
            self.assertIn("https://bot.example/apk-upload/", markup["web_app"]["url"])


if __name__ == "__main__":
    unittest.main()
