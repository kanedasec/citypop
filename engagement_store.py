"""Persistent engagement metadata for City Pop."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from payload_runner import safe_slug


class EngagementStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.rows = self._load()

    def _load(self) -> dict[str, dict]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return {str(row["id"]): row for row in data if isinstance(row, dict) and row.get("id")}
        except (OSError, json.JSONDecodeError, TypeError):
            return {}

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(list(self.rows.values()), indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.path)

    def list(self) -> list[dict]:
        with self.lock:
            return [dict(row) for row in self.rows.values()]

    def upsert(self, name: str, date: str, scope: str, engagement_id: str = "") -> dict:
        now = datetime.now(timezone.utc).isoformat()
        with self.lock:
            identifier = safe_slug(engagement_id or name)
            existing = self.rows.get(identifier)
            row = {
                "id": identifier,
                "name": existing["name"] if existing else name,
                "date": date,
                "scope": scope,
                "created_at": existing.get("created_at", now) if existing else now,
                "updated_at": now,
                "recovered": False,
            }
            self.rows[identifier] = row
            self._save()
            return dict(row)

    def delete(self, engagement_id: str) -> bool:
        with self.lock:
            removed = self.rows.pop(engagement_id, None) is not None
            if removed:
                self._save()
            return removed
