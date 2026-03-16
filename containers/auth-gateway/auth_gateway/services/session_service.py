from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe

from auth_gateway.models.session import OIDCStateRecord, SessionRecord
from auth_gateway.storage.sqlite import SQLiteStorage


class SessionService:
    def __init__(self, storage: SQLiteStorage, default_session_minutes: int, oidc_state_ttl_minutes: int):
        self.storage = storage
        self.default_session_minutes = default_session_minutes
        self.oidc_state_ttl_minutes = oidc_state_ttl_minutes

    def get_session(self, session_id: str | None) -> SessionRecord | None:
        if not session_id:
            return None
        session = self.storage.get_session(session_id)
        if not session:
            return None
        if session.expires_at <= datetime.now(UTC):
            self.storage.delete_session(session_id)
            return None
        return session

    def issue_session(
        self,
        existing_session: SessionRecord | None = None,
        *,
        username: str | None = None,
        email: str | None = None,
        subject: str | None = None,
        groups: list[str] | None = None,
        add_factors: list[str] | None = None,
        metadata: dict | None = None,
        expires_in_minutes: int | None = None,
    ) -> SessionRecord:
        now = datetime.now(UTC)
        session = existing_session or SessionRecord(
            session_id=token_urlsafe(32),
            created_at=now,
            updated_at=now,
            expires_at=now + timedelta(minutes=expires_in_minutes or self.default_session_minutes),
        )
        if username is not None:
            session.username = username
        if email is not None:
            session.email = email
        if subject is not None:
            session.subject = subject
        if groups is not None:
            session.groups = groups
        if metadata:
            session.metadata.update(metadata)
        if add_factors:
            was_unauthenticated = not session.auth_factors
            merged_factors = set(session.auth_factors)
            merged_factors.update(add_factors)
            session.auth_factors = sorted(merged_factors)
            # Prevent session fixation: regenerate session ID on first authentication
            if was_unauthenticated and existing_session:
                self.storage.delete_session(existing_session.session_id)
                session.session_id = token_urlsafe(32)
        requested_expiry = now + timedelta(minutes=expires_in_minutes or self.default_session_minutes)
        session.expires_at = min(session.expires_at, requested_expiry) if existing_session else requested_expiry
        session.updated_at = now
        self.storage.save_session(session)
        return session

    def delete_session(self, session_id: str | None) -> None:
        if session_id:
            self.storage.delete_session(session_id)

    def create_oidc_state(self, method_name: str, host: str, next_url: str) -> OIDCStateRecord:
        now = datetime.now(UTC)
        state = OIDCStateRecord(
            state=token_urlsafe(24),
            nonce=token_urlsafe(24),
            method_name=method_name,
            host=host,
            next_url=next_url,
            created_at=now,
            expires_at=now + timedelta(minutes=self.oidc_state_ttl_minutes),
        )
        self.storage.save_oidc_state(state)
        return state

    def consume_oidc_state(self, state_value: str) -> OIDCStateRecord | None:
        oidc_state = self.storage.get_oidc_state(state_value)
        if not oidc_state:
            return None
        self.storage.delete_oidc_state(state_value)
        if oidc_state.expires_at <= datetime.now(UTC):
            return None
        return oidc_state
