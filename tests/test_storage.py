import json
import multiprocessing
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portal"))
from storage import ProcessLock, atomic_write, read_json
from envfile import set_values


def increment(path):
    lock = ProcessLock(path + ".lock")
    for _ in range(20):
        with lock:
            value = read_json(path)["count"]
            with lock: atomic_write(path, json.dumps({"count": value + 1}))


class StorageTests(unittest.TestCase):
    def test_concurrent_processes_do_not_lose_updates(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "db.json")
            atomic_write(path, '{"count":0}')
            processes = [multiprocessing.get_context("spawn").Process(target=increment, args=(path,)) for _ in range(3)]
            for p in processes: p.start()
            for p in processes:
                p.join(20)
                self.assertEqual(p.exitcode, 0)
            self.assertEqual(read_json(path)["count"], 60)

    def test_env_password_special_characters_are_literal_on_update(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "secrets.env"
            set_values(path, {"PASSWORD": "old", "OTHER": "keep"})
            value = 'a&b|c\\d$e"f\'g'
            set_values(path, {"PASSWORD": value})
            self.assertEqual(path.read_text().splitlines(), ["OTHER=keep", "PASSWORD=" + value])
            with self.assertRaises(ValueError): set_values(path, {"PASSWORD": "a\nb"})
