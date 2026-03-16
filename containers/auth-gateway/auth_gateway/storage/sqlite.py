import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

from auth_gateway.models.session import OIDCStateRecord, SessionRecord


class SQLiteStorage:
    def __init__(self, database_path: Path):
        self.database_path = database_path
        self._lock = threading.Lock()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    username TEXT,
                    email TEXT,
                    subject TEXT,
                    groups_json TEXT NOT NULL,
                    auth_factors_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS oidc_states (
                    state TEXT PRIMARY KEY,
                    nonce TEXT NOT NULL,
                    method_name TEXT NOT NULL,
                    host TEXT NOT NULL,
                    next_url TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
                """
            )
            connection.commit()

    @staticmethod
    def _to_iso(value: datetime) -> str:
        return value.astimezone(UTC).isoformat()

    @staticmethod
    def _from_iso(value: str) -> datetime:
        return datetime.fromisoformat(value)

    def save_session(self, session: SessionRecord) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO sessions (
                    session_id, created_at, updated_at, expires_at, username, email, subject,
                    groups_json, auth_factors_json, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    self._to_iso(session.created_at),
                    self._to_iso(session.updated_at),
                    self._to_iso(session.expires_at),
                    session.username,
                    session.email,
                    session.subject,
                    json.dumps(session.groups),
                    json.dumps(session.auth_factors),
                    json.dumps(session.metadata),
                ),
            )
            connection.commit()

    def get_session(self, session_id: str) -> SessionRecord | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if not row:
            return None
        return SessionRecord(
            session_id=row["session_id"],
            created_at=self._from_iso(row["created_at"]),
            updated_at=self._from_iso(row["updated_at"]),
            expires_at=self._from_iso(row["expires_at"]),
            username=row["username"],
            email=row["email"],
            subject=row["subject"],
            groups=json.loads(row["groups_json"]),
            auth_factors=json.loads(row["auth_factors_json"]),
            metadata=json.loads(row["metadata_json"]),
        )

    def delete_session(self, session_id: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            connection.commit()

    def save_oidc_state(self, oidc_state: OIDCStateRecord) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO oidc_states (
                    state, nonce, method_name, host, next_url, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    oidc_state.state,
                    oidc_state.nonce,
                    oidc_state.method_name,
                    oidc_state.host,
                    oidc_state.next_url,
                    self._to_iso(oidc_state.created_at),
                    self._to_iso(oidc_state.expires_at),
                ),
            )
            connection.commit()

    def get_oidc_state(self, state: str) -> OIDCStateRecord | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM oidc_states WHERE state = ?",
                (state,),
            ).fetchone()
        if not row:
            return None
        return OIDCStateRecord(
            state=row["state"],
            nonce=row["nonce"],
            method_name=row["method_name"],
            host=row["host"],
            next_url=row["next_url"],
            created_at=self._from_iso(row["created_at"]),
            expires_at=self._from_iso(row["expires_at"]),
        )

    def delete_oidc_state(self, state: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM oidc_states WHERE state = ?", (state,))
            connection.commit()
