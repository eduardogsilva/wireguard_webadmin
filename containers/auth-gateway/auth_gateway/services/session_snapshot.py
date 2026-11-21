import json
import logging
import os
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from auth_gateway.config_loader import RuntimeConfigStore
from auth_gateway.models.session import SessionRecord
from auth_gateway.services.session_service import session_id_hash, session_is_valid
from auth_gateway.storage.sqlite import SQLiteStorage

logger = logging.getLogger("uvicorn.error")

SNAPSHOT_INTERVAL_SECONDS = 30
# A session used in the last minutes is online. The last access is written at most every 5 minutes, so the window
# must be longer than that.
ONLINE_WINDOW = timedelta(minutes=10)


class SessionSnapshot:
    """
    Active sessions published for the WireGuard WebAdmin (read by Django on the primary server and reported by the
    cluster agent on workers). The file is only rewritten when its content changes: an active session is published
    as online without a timestamp, so using it does not change the snapshot.
    """

    def __init__(self, storage: SQLiteStorage, config_store: RuntimeConfigStore, path: Path):
        self.storage = storage
        self.config_store = config_store
        self.path = path
        self._lock = threading.Lock()
        self._written = None

    @staticmethod
    def _entry(session: SessionRecord, now: datetime) -> dict:
        last_seen = session.metadata.get("last_seen") or session.created_at.isoformat()
        online = now - datetime.fromisoformat(last_seen) < ONLINE_WINDOW
        entry = {
            "id": session_id_hash(session.session_id),
            "username": session.username or "",
            "email": session.email or "",
            "groups": session.groups,
            "factors": session.auth_factors,
            "host": session.metadata.get("host", ""),
            "client_ip": session.metadata.get("client_ip", ""),
            "user_agent": session.metadata.get("user_agent", ""),
            "created_at": session.created_at.isoformat(),
            "expires_at": session.expires_at.isoformat(),
            "online": online,
        }
        if not online:
            entry["last_seen"] = last_seen
        return entry

    def refresh(self) -> None:
        with self._lock:
            now = datetime.now(UTC)
            self.storage.delete_expired(now)
            try:
                runtime_config = self.config_store.get()
            except Exception as error:
                logger.warning("Session snapshot skipped: configuration not loaded (%s)", error)
                return

            entries = []
            for session in self.storage.list_sessions():
                if not session_is_valid(session, runtime_config):
                    self.storage.delete_session(session.session_id)
                    continue
                entries.append(self._entry(session, now))

            content = json.dumps({"sessions": entries}, indent=2, sort_keys=True) + "\n"
            if content == self._written:
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = self.path.with_name(f"{self.path.name}.tmp")
            temp_path.write_text(content, encoding="utf-8")
            os.replace(temp_path, self.path)
            self._written = content
