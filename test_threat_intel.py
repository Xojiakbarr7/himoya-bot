"""Passive scanner boundaries; fixtures are harmless, networking is mocked."""
import asyncio
from collections import OrderedDict
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch
import zipfile

import main
from threat_intel import DomainReputation, HashReputation, MAX_MANIFEST_BYTES, inspect_apk, manifest_permissions


def apk(manifest):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", b"harmless test fixture")
    return stream.getvalue()


def axml_permission(permission="android.permission.READ_SMS"):
    strings = ["uses-permission", "name", permission, "http://schemas.android.com/apk/res/android"]
    body, offsets = b"", []
    for value in strings:
        raw = value.encode()
        offsets.append(len(body))
        body += bytes([len(value), len(raw)]) + raw + b"\0"
    body += b"\0" * (-len(body) % 4)
    pool = struct.pack("<HHIIIIII", 1, 28, 28 + 4 * len(strings) + len(body), len(strings), 0, 0x100, 28 + 4 * len(strings), 0)
    pool += struct.pack("<" + "I" * len(strings), *offsets) + body
    node = struct.pack("<HHIII", 0x102, 16, 56, 1, 0xffffffff)
    node += struct.pack("<IIHHHHHH", 0xffffffff, 0, 20, 20, 1, 0, 0, 0)
    node += struct.pack("<IIIHBBI", 3, 1, 2, 8, 0, 3, 2)
    return struct.pack("<HHI", 3, 8, 8 + len(pool) + len(node)) + pool + node


class PassiveScannerTests(unittest.TestCase):
    def test_exact_domain_only_and_staleness(self):
        feed = DomainReputation(Path("unused"))
        feed.hosts, feed.updated_at = {"bad.test"}, time.time()
        self.assertTrue(feed.matches("BAD.TEST."))
        self.assertFalse(feed.matches("safe.bad.test"))
        self.assertFalse(feed.matches("bad.test.evil.test"))
        feed.updated_at -= 8 * 86400
        self.assertFalse(feed.matches("bad.test"))

    def test_feed_rejects_partial_data_and_shared_roots(self):
        with self.assertRaises(ValueError):
            DomainReputation.parse(b"bad.test\n")
        source = "\n".join([f"x{i}.bad.test" for i in range(100)] + ["t.me", "invalid host", "# comment"])
        parsed = DomainReputation.parse(source.encode())
        self.assertEqual(len(parsed), 100)
        self.assertNotIn("t.me", parsed)

    def test_list_match_upgrades_local_link_verdict(self):
        feed = DomainReputation(Path("unused"))
        feed.hosts, feed.updated_at = {"listed.test"}, time.time()
        with patch.object(main, "THREAT_INTEL", feed):
            result = main.analyze({"text": "https://listed.test/private?token=secret"})
        self.assertGreaterEqual(result["score"], 90)
        self.assertTrue(any("Phishing.Database" in reason for reason in result["reasons"]))

    def test_plain_manifest_and_hash(self):
        data = apk(b'<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-permission android:name="android.permission.READ_SMS"/></manifest>')
        result = inspect_apk(data)
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
        self.assertTrue(result["manifest_read"])
        self.assertEqual(result["permissions"], ["android.permission.READ_SMS"])

    def test_real_binary_axml_permission(self):
        self.assertEqual(manifest_permissions(axml_permission()), {"android.permission.READ_SMS"})
        self.assertTrue(inspect_apk(apk(axml_permission()))["manifest_read"])

    def test_truncated_axml_is_rejected(self):
        for cut in (0, 2, 7, 20, len(axml_permission()) - 1):
            with self.assertRaises((ValueError, struct.error)):
                manifest_permissions(axml_permission()[:cut])

    def test_oversize_manifest_and_non_apk_are_not_marked_safe(self):
        self.assertFalse(inspect_apk(apk(b"x" * (MAX_MANIFEST_BYTES + 1)))["manifest_read"])
        self.assertFalse(inspect_apk(b"not an apk")["valid_apk"])
        self.assertFalse(inspect_apk(apk(b'<!DOCTYPE manifest [<!ENTITY x "test">]><manifest/>'))["manifest_read"])


class Response:
    def __init__(self, status=200, body=None):
        self.status = status
        self.raw = json.dumps(body or {}).encode()
        self.content = self
    async def __aenter__(self):
        return self
    async def __aexit__(self, *args):
        return False
    async def iter_chunked(self, size):
        for pos in range(0, len(self.raw), 7):
            yield self.raw[pos:pos + 7]


class AsyncScannerTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_key_does_not_send_request(self):
        session = Mock()
        self.assertEqual((await HashReputation().lookup(session, "a" * 64))["status"], "disabled")
        session.get.assert_not_called()

    async def test_vt_sends_only_hash_and_unknown_is_not_clean(self):
        session = Mock()
        session.get.return_value = Response(404)
        self.assertEqual((await HashReputation("fake-key").lookup(session, "b" * 64))["status"], "not_found")
        self.assertEqual(session.get.call_args.args[0], "https://www.virustotal.com/api/v3/files/" + "b" * 64)
        self.assertNotIn("data", session.get.call_args.kwargs)

    async def test_vt_streamed_response_cache_and_rate_limit(self):
        session = Mock()
        session.get.return_value = Response(body={"data": {"attributes": {"last_analysis_stats": {"malicious": 4, "suspicious": 1}}}})
        lookup = HashReputation("fake-key")
        result = await lookup.lookup(session, "a" * 64)
        self.assertEqual(result["malicious"], 4)
        self.assertEqual(await lookup.lookup(session, "a" * 64), result)
        self.assertEqual((await lookup.lookup(session, "b" * 64))["status"], "rate_limited")
        self.assertEqual(session.get.call_count, 1)

    async def test_apk_requires_owner_consent_before_getfile(self):
        message = {"chat": {"id": 10, "type": "private"}, "document": {"file_id": "fake", "file_name": "test.apk", "file_size": 100}}
        with patch.object(main, "api", AsyncMock()) as api, patch.object(main, "APK_REQUESTS", OrderedDict()), patch.object(main, "run_apk_inspection", AsyncMock()) as run:
            await main.handle_manual_scan(None, message)
            self.assertNotIn("getFile", [call.args[1] for call in api.await_args_list])
            token = next(iter(main.APK_REQUESTS))
            await main.handle_apk_callback(None, {"id": "query", "from": {"id": 99}, "data": "apk:scan:" + token})
            run.assert_not_awaited()
            self.assertIn(token, main.APK_REQUESTS)

    async def test_telegram_path_traversal_is_rejected(self):
        session = Mock()
        with patch.object(main, "api", AsyncMock(return_value={"file_path": "../escape.apk", "file_size": 100})), patch.object(main, "send_text", AsyncMock()) as send:
            await main.run_apk_inspection(session, 10, {"file_id": "fake", "name": "test.apk"})
            session.get.assert_not_called()
            self.assertIn("tugatib bo‘lmadi", send.await_args.args[2])


if __name__ == "__main__":
    unittest.main()
