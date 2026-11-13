"""Persistence contract using SQLite SQL adapter; real provider smoke test needs credentials."""
import sqlite3
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch
import main


class Connection:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
    def __enter__(self):
        return self
    def __exit__(self, kind, value, trace):
        if kind:
            self.db.rollback()
        else:
            self.db.commit()
        self.db.close()
    def execute(self, sql, values):
        sql = sql.replace('%s', '?').replace(' OFFSET ', ' LIMIT -1 OFFSET ')
        return self.db.execute(sql, values)


class PersistenceTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / 'history.sqlite')
        self.driver = SimpleNamespace(connect=lambda *a, **kw: Connection(self.path), Error=sqlite3.Error)
        self.module = patch.dict(sys.modules, psycopg=self.driver)
        self.module.start()
        self.history = main.PostgresMessageHistory('unused')
        self.message = {'chat': {'id': 20}, 'message_id': 1, 'from': {'id': 20},
                        'caption': '<hello>', 'photo': [{'file_id': 'file-reference'}]}
    def tearDown(self):
        self.module.stop()
        self.temp.cleanup()
    def test_restart_preserves_mode_text_media_and_owner_scope(self):
        self.history.set_enabled(10, True)
        self.history.remember(10, 'c', self.message)
        self.assertEqual(self.history.mark_deleted(10, 'c', 20, [1]), (1, 0))
        restarted = main.PostgresMessageHistory('unused')
        self.assertTrue(restarted.enabled(10))
        record = restarted.deleted(10)[0]
        self.assertEqual(record['text'], '<hello>')
        self.assertEqual(record['media']['file_id'], 'file-reference')
        self.assertIsNone(restarted.detail(30, record['token']))
        restarted.clear(10)
        self.assertEqual(self.history.deleted(10), [])
    def test_expired_rows_purged_and_ignored_deletions_suppressed(self):
        self.history.remember(10, 'c', self.message, ignored=True)
        self.assertEqual(self.history.mark_deleted(10, 'c', 20, [1]), (0, 0))
        self.history._execute([('UPDATE qalqon_history SET expires=%s', (0,))])
        self.history.prune()
        self.assertEqual(self.history._execute([('SELECT count(*) FROM qalqon_history', ())]), [(0,)])
    def test_database_error_is_redacted_and_retryable(self):
        with patch.object(self.driver, 'connect', side_effect=sqlite3.OperationalError('password-private')):
            with self.assertRaises(main.TelegramTemporaryError) as error:
                self.history.enabled(10)
            self.assertNotIn('password-private', str(error.exception))
