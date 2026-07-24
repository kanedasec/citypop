import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GOOGLE_API_KEY = re.compile(rb"AIza[0-9A-Za-z_-]{35}")


class SecretHygieneTests(unittest.TestCase):
    def test_tracked_files_do_not_contain_google_api_keys(self):
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
        matches = []
        for relative in result.stdout.split(b"\0"):
            if not relative:
                continue
            path = ROOT / relative.decode("utf-8", errors="surrogateescape")
            if path.is_file() and GOOGLE_API_KEY.search(path.read_bytes()):
                matches.append(str(path.relative_to(ROOT)))
        self.assertEqual(matches, [], f"Google API key pattern found in: {matches}")


if __name__ == "__main__":
    unittest.main()
