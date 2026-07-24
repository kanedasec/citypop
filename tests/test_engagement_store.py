import tempfile
import unittest
from pathlib import Path

from citypop.engagement_store import EngagementStore


class EngagementStoreTests(unittest.TestCase):
    def test_create_update_reload_and_delete(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "engagements.json"
            store = EngagementStore(path)
            created = store.upsert("Home Lab", "2026-07-19", "192.168.18.0/24")
            self.assertEqual(created["id"], "Home_Lab")
            updated = store.upsert("Ignored Rename", "2026-07-20", "lab AP", created["id"])
            self.assertEqual(updated["name"], "Home Lab")
            self.assertEqual(updated["scope"], "lab AP")
            reloaded = EngagementStore(path)
            self.assertEqual(reloaded.list()[0]["date"], "2026-07-20")
            self.assertTrue(reloaded.delete(created["id"]))
            self.assertEqual(reloaded.list(), [])


if __name__ == "__main__":
    unittest.main()
