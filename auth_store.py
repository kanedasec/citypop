from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash


MIN_PASSWORD_LENGTH = 15
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


class AuthStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _read(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(".tmp")
        temp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        os.chmod(temp, 0o600)
        temp.replace(self.path)

    @staticmethod
    def validate(username: str, password: str) -> None:
        if not USERNAME_RE.fullmatch(username):
            raise ValueError("username must be 3–32 letters, numbers, dots, dashes, or underscores")
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
        if len(password) > 256:
            raise ValueError("password must be no more than 256 characters")

    def initialized(self) -> bool:
        data = self._read()
        return bool(data.get("username") and data.get("password_hash"))

    def username(self) -> str:
        return str(self._read().get("username", ""))

    def setup(self, username: str, password: str) -> None:
        self.validate(username, password)
        with self._lock:
            if self.initialized():
                raise RuntimeError("administrator account is already configured")
            self._write({
                "username": username,
                "password_hash": generate_password_hash(password, method="scrypt"),
            })

    def verify(self, username: str, password: str) -> bool:
        data = self._read()
        stored_username = str(data.get("username", ""))
        password_hash = str(data.get("password_hash", ""))
        return bool(
            stored_username
            and password_hash
            and username == stored_username
            and check_password_hash(password_hash, password)
        )

    def update(self, current_password: str, username: str, new_password: str = "") -> None:
        with self._lock:
            data = self._read()
            current_username = str(data.get("username", ""))
            password_hash = str(data.get("password_hash", ""))
            if not current_username or not password_hash:
                raise RuntimeError("administrator account is not configured")
            if not check_password_hash(password_hash, current_password):
                raise PermissionError("current password is incorrect")
            next_password = new_password or current_password
            self.validate(username, next_password)
            self._write({
                "username": username,
                "password_hash": (
                    generate_password_hash(new_password, method="scrypt")
                    if new_password else password_hash
                ),
            })
