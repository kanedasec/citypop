import json
import tempfile
import unittest
from pathlib import Path

from auth_store import AuthStore, PairingStore


class AuthStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "auth.json"
        self.store = AuthStore(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def test_setup_hashes_password_and_can_verify_it(self):
        password = "a sufficiently long passphrase"
        self.store.setup("operator", password)
        data = json.loads(self.path.read_text())
        self.assertNotEqual(data["password_hash"], password)
        self.assertNotIn(password, self.path.read_text())
        self.assertTrue(self.store.verify("operator", password))
        self.assertFalse(self.store.verify("operator", "incorrect password value"))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_short_password_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least 15"):
            self.store.setup("operator", "too-short")

    def test_setup_cannot_replace_an_existing_account(self):
        self.store.setup("operator", "a sufficiently long passphrase")
        with self.assertRaisesRegex(RuntimeError, "already configured"):
            self.store.setup("attacker", "another sufficient passphrase")

    def test_auth_version_increments_after_account_change(self):
        self.store.setup("operator", "a sufficiently long passphrase")
        self.assertEqual(self.store.version(), 1)
        self.store.update(
            "a sufficiently long passphrase", "operator",
            "a different sufficiently long passphrase",
        )
        self.assertEqual(self.store.version(), 2)

    def test_pairing_code_is_single_use(self):
        pairing_path = Path(self.temp.name) / "setup.json"
        from werkzeug.security import generate_password_hash
        pairing_path.write_text(json.dumps({
            "code_hash": generate_password_hash("ABC-123-PAIR", method="scrypt"),
        }))
        pairing = PairingStore(pairing_path)
        self.assertTrue(pairing.required())
        self.assertFalse(pairing.verify_and_consume("wrong"))
        self.assertTrue(pairing.verify_and_consume("ABC-123-PAIR"))
        self.assertFalse(pairing.required())


if __name__ == "__main__":
    unittest.main()
