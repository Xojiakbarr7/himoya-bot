"""Security boundaries and existing protection regressions; no real Telegram calls."""
import asyncio
import logging
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
import main


SECRET = "test-secret-" + "s" * 48


def private_update(update_id=1, actor=10, chat=10, text="/start"):
    return {"update_id": update_id, "message": {
        "message_id": 1, "chat": {"id": chat, "type": "private"},
        "from": {"id": actor, "first_name": "User"}, "text": text,
    }}


def business_update(update_id=1, text="https://example.com", sender=20):
    return {"update_id": update_id, "business_message": {
        "message_id": update_id, "business_connection_id": "c",
        "chat": {"id": 20, "type": "private"},
        "from": {"id": sender, "first_name": "User"}, "text": text,
    }}


class WebhookSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.sqlite3"
        self.store = main.Store(self.path)
        self.api = AsyncMock(return_value={})
        self.api_patch = patch.object(main, "api", self.api)
        self.api_patch.start()
        self.limiter_patch = patch.object(main, "PRIVATE_LIMITER", main.InteractionLimiter())
        self.limiter_patch.start()
        server = TestServer(main.create_webhook_app(None, self.store, SECRET))
        await server.start_server(auto_decompress=False, access_log=None)
        self.client = TestClient(server)
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        self.store.db.close()
        self.api_patch.stop()
        self.limiter_patch.stop()
        self.temp.cleanup()

    async def post(self, value=None, **kwargs):
        headers = kwargs.pop("headers", {"X-Telegram-Bot-Api-Secret-Token": SECRET, "Content-Type": "application/json"})
        return await self.client.post(main.WEBHOOK_PATH, json=value, headers=headers, **kwargs)

    async def test_missing_wrong_unicode_and_duplicate_secrets_rejected(self):
        for headers in ({}, {"X-Telegram-Bot-Api-Secret-Token": "wrong"},
                        {"X-Telegram-Bot-Api-Secret-Token": "noto‘g‘ri"},
                        [("X-Telegram-Bot-Api-Secret-Token", SECRET)] * 2):
            response = await self.post(private_update(), headers=headers)
            self.assertEqual(response.status, 403)
        self.api.assert_not_awaited()

    async def test_malformed_shapes_rejected_before_processing(self):
        bad = [None, [], {}, {"update_id": True},
               {"update_id": 1, "message": []},
               {"update_id": 1, "message": {"chat": []}},
               private_update() | {"callback_query": {}},
               private_update() | {"message": private_update()["message"] | {"entities": {}}}]
        for value in bad:
            response = await self.post(value)
            self.assertEqual(response.status, 400, value)
        self.api.assert_not_awaited()

    async def test_content_type_encoding_and_size_rejected(self):
        for headers, data, status in [
            ({"Content-Type": "text/plain"}, "{}", 415),
            ({"Content-Type": "application/json", "Content-Encoding": "gzip"}, "{}", 415),
            ({"Content-Type": "application/json"}, "x" * (main.MAX_WEBHOOK_BYTES + 1), 413),
        ]:
            headers["X-Telegram-Bot-Api-Secret-Token"] = SECRET
            response = await self.client.post(main.WEBHOOK_PATH, headers=headers, data=data)
            self.assertEqual(response.status, status)
        self.api.assert_not_awaited()

    async def test_deeply_nested_input_rejected(self):
        nested = {}
        for _ in range(30):
            nested = {"x": nested}
        response = await self.post({"update_id": 1, "unused": nested})
        self.assertEqual(response.status, 400)

    async def test_duplicate_keys_and_nonstandard_json_rejected(self):
        for raw in ('{"update_id":1,"update_id":2}', '{"update_id":1,"x":NaN}'):
            response = await self.client.post(main.WEBHOOK_PATH, data=raw, headers={
                "X-Telegram-Bot-Api-Secret-Token": SECRET, "Content-Type": "application/json",
            })
            self.assertEqual(response.status, 400)
        self.api.assert_not_awaited()

    async def test_queue_overload_is_retryable_not_acknowledged(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def slow(*args):
            entered.set()
            await release.wait()
        with patch.object(main, "MAX_PENDING_UPDATES", 1), patch.object(main, "process_update", new=AsyncMock(side_effect=slow)) as process:
            first = asyncio.create_task(self.post(private_update(1)))
            await asyncio.wait_for(entered.wait(), 1)
            try:
                self.assertEqual((await self.post(private_update(2))).status, 503)
                self.assertFalse(self.store.update_processed(2))
            finally:
                release.set()
            self.assertEqual((await first).status, 200)
            self.assertEqual((await self.post(private_update(2))).status, 200)
            self.assertEqual(process.await_count, 2)

    async def test_concurrent_duplicates_run_only_once_and_survive_db_reopen(self):
        async def slow(*args):
            await asyncio.sleep(0.02)
        with patch.object(main, "process_update", new=AsyncMock(side_effect=slow)) as process:
            responses = await asyncio.gather(self.post(private_update()), self.post(private_update()))
            self.assertTrue(all(r.status == 200 for r in responses))
            self.assertEqual(process.await_count, 1)
        reopened = main.Store(self.path)
        self.assertTrue(reopened.update_processed(1))
        reopened.db.close()

    async def test_failed_processing_is_retryable(self):
        with patch.object(main, "process_update", new=AsyncMock(side_effect=[main.TelegramAPIError("failed"), None])) as process:
            self.assertEqual((await self.post(private_update())).status, 503)
            self.assertFalse(self.store.update_processed(1))
            self.assertEqual((await self.post(private_update())).status, 200)
            self.assertEqual(process.await_count, 2)

    async def test_private_sender_cannot_control_someone_elses_chat(self):
        with patch.object(main, "process_update", new=AsyncMock()) as process:
            self.assertEqual((await self.post(private_update(actor=20, chat=10))).status, 200)
            process.assert_not_awaited()
        self.api.assert_not_awaited()

    async def test_callback_cannot_change_another_users_settings(self):
        self.store.set_outgoing_warning(10, True)
        update = {"update_id": 1, "callback_query": {
            "id": "q", "from": {"id": 20}, "data": "outgoing_warning:off",
            "message": {"message_id": 5, "chat": {"id": 10, "type": "private"}},
        }}
        self.assertEqual((await self.post(update)).status, 200)
        self.assertTrue(self.store.outgoing_warning_enabled(10))
        self.assertFalse(self.store.outgoing_warning_enabled(20))
        self.api.assert_awaited_once_with(None, "answerCallbackQuery", {"callback_query_id": "q"})

    async def test_valid_callback_changes_only_owners_settings(self):
        update = {"update_id": 1, "callback_query": {
            "id": "q", "from": {"id": 10}, "data": "outgoing_warning:on",
            "message": {"message_id": 5, "chat": {"id": 10, "type": "private"}},
        }}
        self.assertEqual((await self.post(update)).status, 200)
        self.assertTrue(self.store.outgoing_warning_enabled(10))
        self.assertFalse(self.store.outgoing_warning_enabled(20))
        self.assertTrue(any(call.args[2].get("reply_markup") == main.MAIN_KEYBOARD for call in self.api.await_args_list))

    async def test_plain_message_unknown_command_and_menu_button_restore_keyboard(self):
        for update_id, text in enumerate(("Salom", "/unknown", main.BUTTON_SCAN), 1):
            self.api.reset_mock()
            self.assertEqual((await self.post(private_update(update_id, text=text))).status, 200)
            markup = self.api.await_args_list[-1].args[2]["reply_markup"]
            self.assertTrue(markup["is_persistent"])
            self.assertFalse(markup["one_time_keyboard"])

    async def test_inline_settings_also_refresh_main_keyboard(self):
        self.assertEqual((await self.post(private_update(text=main.BUTTON_OUTGOING_WARNING))).status, 200)
        markups = [call.args[2].get("reply_markup", {}) for call in self.api.await_args_list]
        self.assertIn(main.MAIN_KEYBOARD, markups)
        self.assertTrue(any("inline_keyboard" in markup for markup in markups))

    async def test_private_spam_limited_without_limiting_business_deletion(self):
        main.PRIVATE_LIMITER = main.InteractionLimiter(capacity=2)
        with patch.object(main, "process_update", new=AsyncMock()) as process:
            for update_id in range(1, 6):
                self.assertEqual((await self.post(private_update(update_id))).status, 200)
            self.assertEqual(process.await_count, 2)
        self.store.save_connection({"id": "c", "user": {"id": 10}, "user_chat_id": 10, "is_enabled": True})
        self.store.set_auto_delete(10, True)
        self.assertEqual((await self.post(business_update(10))).status, 200)
        methods = [call.args[1] for call in self.api.await_args_list]
        self.assertIn("deleteBusinessMessages", methods)

    async def test_business_route_comes_from_telegram_not_supplied_owner(self):
        self.api.return_value = {"id": "c", "user": {"id": 10}, "user_chat_id": 10, "is_enabled": True}
        update = {"update_id": 1, "business_connection": {"id": "c", "user": {"id": 99}, "user_chat_id": 99}}
        self.assertEqual((await self.post(update)).status, 200)
        self.assertEqual(self.store.connection("c"), (10, 10))

    async def test_new_contact_silent_and_existing_link_and_apk_deletion_preserved(self):
        self.store.save_connection({"id": "c", "user": {"id": 10}, "user_chat_id": 10, "is_enabled": True})
        self.store.set_auto_delete(10, True)
        self.assertEqual((await self.post(business_update(1, "Salom"))).status, 200)
        self.api.assert_not_awaited()
        for update in [business_update(2), business_update(3, "https://example.com", sender=10)]:
            self.assertEqual((await self.post(update)).status, 200)
        apk = business_update(4, "")
        apk["business_message"]["document"] = {"file_name": "app.apk"}
        self.assertEqual((await self.post(apk)).status, 200)
        deleted = [call for call in self.api.await_args_list if call.args[1] == "deleteBusinessMessages"]
        self.assertEqual(len(deleted), 2)

    async def test_health_is_minimal_and_headers_hide_runtime(self):
        response = await self.client.get("/healthz")
        self.assertEqual(await response.json(), {"ok": True})
        self.assertNotIn("Server", response.headers)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual((await self.client.head("/")).status, 200)

    async def test_group_link_deletion_preserved(self):
        update = private_update()
        update["message"]["chat"] = {"id": -100123, "type": "supergroup"}
        update["message"]["text"] = "https://example.com"
        self.assertEqual((await self.post(update)).status, 200)
        self.assertIn("deleteMessage", [call.args[1] for call in self.api.await_args_list])

    async def test_removed_photo_and_foreign_number_modes_do_nothing(self):
        self.store.save_connection({"id": "c", "user": {"id": 10}, "user_chat_id": 10, "is_enabled": True})
        update = business_update(1, "+44 7700 900123")
        update["business_message"]["photo"] = [{"file_id": "TEST_FILE_ID_1234567890"}]
        self.assertEqual((await self.post(update)).status, 200)
        self.api.assert_not_awaited()
        labels = str(main.MAIN_KEYBOARD)
        self.assertNotIn("Xalqaro raqam", labels)
        self.assertNotIn("rasmlarimni", labels)

    async def test_old_buttons_cannot_reactivate_removed_modes(self):
        for update_id, data in enumerate(("photo_test:new", "unknown_sender:on"), 1):
            update = {"update_id": update_id, "callback_query": {
                "id": str(update_id), "from": {"id": 10}, "data": data,
                "message": {"message_id": 5, "chat": {"id": 10, "type": "private"}},
            }}
            self.assertEqual((await self.post(update)).status, 200)
        self.assertFalse(any(call.args[1] == "sendPhoto" for call in self.api.await_args_list))
        tables = {row[0] for row in self.store.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn("photo_tests", tables)
        self.assertNotIn("sender_profiles", tables)






    async def test_transient_delete_failure_not_marked_processed(self):
        self.store.save_connection({"id": "c", "user": {"id": 10}, "user_chat_id": 10, "is_enabled": True})
        self.store.set_auto_delete(10, True)
        self.api.side_effect = main.TelegramTemporaryError("rate limited")
        self.assertEqual((await self.post(business_update())).status, 503)
        self.assertFalse(self.store.update_processed(1))


class LocalSecurityTests(unittest.TestCase):
    def test_secret_redaction_includes_exception_tracebacks(self):
        token = "123456789:" + "s" * 35
        record = logging.LogRecord("test", logging.WARNING, "", 0, "https://api.telegram.org/bot%s/getMe", (token,), None)
        formatted = main.SafeLogFormatter().format(record)
        self.assertNotIn(token, formatted)
        self.assertIn("[REDACTED]", formatted)

    def test_limiter_memory_bounded(self):
        limiter = main.InteractionLimiter(capacity=1, max_keys=3)
        for value in range(100):
            limiter.allow(("private", value))
        self.assertLessEqual(len(limiter.entries), 3)
        self.assertFalse(limiter.allow(("private", 99)))

    def test_database_permissions_are_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            store = main.Store(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            store.db.close()

    def test_long_html_fields_remain_well_formed(self):
        from xml.etree import ElementTree
        text = main.alert_message({"level": "YUQORI XAVF", "sender": "<&" * 1024,
            "file_name": "<&" * 1024, "links": [{"host": "<&" * 1024}] * 3,
            "reasons": ["<&" * 1024] * 5})
        root = ElementTree.fromstring("<root>" + text + "</root>")
        self.assertLess(len("".join(root.itertext())), 4096)


class TelegramTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_menu_default_only_for_private_bot_messages_without_inline_markup(self):
        sent = []
        async def receive(request):
            sent.append(await request.json())
            return web.json_response({"ok": True, "result": {}})
        app = web.Application()
        app.router.add_post("/sendMessage", receive)
        server = TestServer(app)
        await server.start_server(access_log=None)
        try:
            async with aiohttp.ClientSession() as session:
                with patch.object(main, "API_BASE", str(server.make_url("/")).rstrip("/")):
                    await main.api(session, "sendMessage", {"chat_id": 10, "text": "Hello"})
                    await main.api(session, "sendMessage", {"chat_id": -10, "text": "Group"})
                    await main.api(session, "sendMessage", {"chat_id": 10, "text": "Business", "business_connection_id": "c"})
                    inline = {"inline_keyboard": [[{"text": "Tips", "callback_data": "tips"}]]}
                    await main.api(session, "sendMessage", {"chat_id": 10, "text": "Inline", "reply_markup": inline})
            self.assertEqual(sent[0]["reply_markup"], main.MAIN_KEYBOARD)
            self.assertNotIn("reply_markup", sent[1])
            self.assertNotIn("reply_markup", sent[2])
            self.assertEqual(sent[3]["reply_markup"], inline)
        finally:
            await server.close()

    async def test_api_redirect_not_followed_and_chunked_json_supported(self):
        leaked = []
        async def redirect(request):
            raise web.HTTPFound("/leak")
        async def leak(request):
            leaked.append(True)
            return web.json_response({"ok": True})
        async def chunked(request):
            response = web.StreamResponse(headers={"Content-Type": "application/json"})
            await response.prepare(request)
            await response.write(b'{"ok":true,')
            await asyncio.sleep(0.01)
            await response.write(b'"result":{"id":10}}')
            await response.write_eof()
            return response
        app = web.Application()
        app.router.add_post("/getMe", redirect)
        app.router.add_route("*", "/leak", leak)
        app.router.add_post("/getBusinessConnection", chunked)
        server = TestServer(app)
        await server.start_server()
        try:
            async with aiohttp.ClientSession() as session:
                with patch.object(main, "API_BASE", str(server.make_url("/")).rstrip("/")):
                    with self.assertRaises(main.TelegramAPIError):
                        await main.api(session, "getMe")
                    self.assertFalse(leaked)
                    self.assertEqual(await main.api(session, "getBusinessConnection"), {"id": 10})
        finally:
            await server.close()


if __name__ == "__main__":
    unittest.main()
