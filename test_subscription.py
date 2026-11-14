"""Required-channel enforcement across private updates, Business and uploads."""
import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import main
from apk_upload import ApkUploadService
from subscription import SubscriptionGate


class SubscriptionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.gate = SubscriptionGate("@qalqon_ai1")
        self.gate.bot_id = 999
        self.status = {"status": "member"}
        self.admin = "administrator"
        async def call(*args):
            method, payload = args[-2:]
            if method == "getChatMember":
                return {"status": self.admin} if payload["user_id"] == 999 else self.status
            return {}
        self.call = AsyncMock(side_effect=call)

    async def test_membership_statuses_and_restricted_membership(self):
        for status in ("creator", "administrator", "member"):
            self.status = {"status": status}
            self.assertEqual(await self.gate.check(self.call, 7, force=True), "member")
        self.status = {"status": "restricted", "is_member": True}
        self.assertEqual(await self.gate.check(self.call, 7, force=True), "member")
        for status in ("left", "kicked", "restricted"):
            self.status = {"status": status}
            self.assertEqual(await self.gate.check(self.call, 7, force=True), "not_member")

    async def test_bot_must_be_admin_and_errors_do_not_unlock(self):
        self.admin = "member"
        self.assertEqual(await self.gate.check(self.call, 7, force=True), "unavailable")
        self.assertFalse(any(c.args[1]["user_id"] == 7 for c in self.call.await_args_list))
        self.call.side_effect = main.TelegramTemporaryError("offline")
        self.assertEqual(await self.gate.check(self.call, 7, force=True), "unavailable")

    async def test_forced_check_detects_unsubscribe_despite_positive_cache(self):
        self.assertEqual(await self.gate.check(self.call, 7), "member")
        self.status = {"status": "left"}
        self.assertEqual(await self.gate.check(self.call, 7, force=True), "not_member")

    async def test_invalid_response_does_not_unlock(self):
        self.status = {}
        self.assertEqual(await self.gate.check(self.call, 7, force=True), "unavailable")

    async def test_disabled_gate_does_not_call_telegram(self):
        self.assertEqual(await SubscriptionGate("").check(self.call, 7), "member")
        self.call.assert_not_awaited()

    async def private_update(self, status, data=None):
        self.status = {"status": status}
        with tempfile.TemporaryDirectory() as directory:
            store = main.Store(Path(directory) / "state.sqlite")
            update = {"update_id": 1, "message": {"message_id": 1, "from": {"id": 7}, "chat": {"id": 7, "type": "private"}, "text": "/start"}}
            if data:
                message = update.pop("message")
                update["callback_query"] = {"id": "query", "from": {"id": 7}, "message": message, "data": data}
            with patch.object(main, "SUBSCRIPTION_GATE", self.gate), patch.object(main, "api", self.call), patch.object(main, "PRIVATE_LIMITER", main.InteractionLimiter()), patch.object(main, "process_update", AsyncMock()) as process:
                await main.process_authenticated_update(None, store, update)
                called = process.await_count
            store.db.close()
        return called

    async def test_start_and_old_callbacks_are_blocked_before_dispatch(self):
        self.assertEqual(await self.private_update("left"), 0)
        self.assertEqual(await self.private_update("left", "history:view:old"), 0)
        messages = [c.args[2] for c in self.call.await_args_list if c.args[1] == "sendMessage"]
        self.assertTrue(any(m["reply_markup"]["inline_keyboard"][0][0]["url"] == "https://t.me/qalqon_ai1" for m in messages))

    async def test_subscriber_dispatches_and_recheck_opens_menu(self):
        self.assertEqual(await self.private_update("member"), 1)
        self.assertEqual(await self.private_update("member", "subscription:check"), 0)
        self.assertTrue(any(c.args[1] == "sendMessage" and c.args[2].get("reply_markup") == main.MAIN_KEYBOARD for c in self.call.await_args_list))

    async def test_nonmember_recheck_keeps_restriction(self):
        self.assertEqual(await self.private_update("left", "subscription:check"), 0)
        self.assertFalse(any(c.args[1] == "sendMessage" and c.args[2].get("reply_markup") == main.MAIN_KEYBOARD for c in self.call.await_args_list))

    async def test_privacy_clear_is_still_accessible(self):
        self.assertEqual(await self.private_update("left", "history:clear"), 1)
        self.assertFalse(any(c.args[1] == "getChatMember" for c in self.call.await_args_list))

    async def test_business_processing_paused_for_nonmember(self):
        self.status = {"status": "left"}
        with tempfile.TemporaryDirectory() as directory:
            store = main.Store(Path(directory) / "state.sqlite")
            store.save_connection({"id": "c", "user": {"id": 7}, "user_chat_id": 7, "is_enabled": True})
            message = {"message_id": 1, "business_connection_id": "c", "from": {"id": 8}, "chat": {"id": 8, "type": "private"}, "text": "https://example.test"}
            with patch.object(main, "SUBSCRIPTION_GATE", self.gate), patch.object(main, "api", self.call), patch.object(main, "SUBSCRIPTION_NOTICE_LIMITER", main.InteractionLimiter()), patch.object(main, "analyze") as analyze:
                await main.process_update(None, store, {"business_message": message})
                analyze.assert_not_called()
            store.db.close()

    async def test_old_upload_link_rechecks_access(self):
        service = ApkUploadService("https://bot.example")
        token = service.issue(7)
        app, scan, jobs = web.Application(), AsyncMock(), set()
        service.register(app, scan, jobs, lambda owner: True, access_owner=AsyncMock(return_value=False))
        async with TestClient(TestServer(app)) as client:
            response = await client.post("/apk-upload/" + token, data=b"fixture", headers={"Origin": service.origin, "X-Upload-Token": token, "Content-Type": "application/octet-stream", "X-Scan-Consent": "yes"})
            self.assertEqual(response.status, 403)
            scan.assert_not_awaited()

    async def test_concurrent_post_authentication_does_not_reuse_token(self):
        service = ApkUploadService("https://bot.example")
        token = service.issue(7)
        async def access(owner):
            await asyncio.sleep(.01)
            return True
        app, scan, jobs = web.Application(), AsyncMock(), set()
        service.register(app, scan, jobs, lambda owner: True, access_owner=access)
        async with TestClient(TestServer(app)) as client:
            headers = {"Origin": service.origin, "X-Upload-Token": token, "Content-Type": "application/octet-stream", "X-Scan-Consent": "yes"}
            responses = await asyncio.gather(*(client.post("/apk-upload/" + token, data=b"fixture", headers=headers) for _ in range(2)))
            self.assertEqual(sorted(r.status for r in responses), [202, 403])
            if jobs:
                await asyncio.gather(*list(jobs))
            self.assertEqual(scan.await_count, 1)


if __name__ == "__main__":
    unittest.main()
