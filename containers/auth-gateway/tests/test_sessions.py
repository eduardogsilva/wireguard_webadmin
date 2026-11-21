import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from auth_gateway.config_loader import RuntimeConfigStore
from auth_gateway.models.auth import UserModel
from auth_gateway.models.runtime import RuntimeConfig
from auth_gateway.services.session_service import (
    SessionService,
    credential_fingerprint,
    session_id_hash,
    session_is_valid,
)
from auth_gateway.services.session_snapshot import SessionSnapshot
from auth_gateway.storage.sqlite import SQLiteStorage

ALICE = UserModel(email="alice@example.test", password_hash="hash-1", totp_secret="SECRET-1")


def write_config(config_dir: Path, users: dict, revoked: list[str] | None = None) -> None:
    (config_dir / "applications.json").write_text(json.dumps({"entries": []}))
    (config_dir / "routes.json").write_text(json.dumps({"entries": {}}))
    (config_dir / "auth_policies.json").write_text(json.dumps({"users": users}))
    if revoked is not None:
        (config_dir / "revoked_sessions.json").write_text(json.dumps({"sessions": revoked}))


class SessionValidityTests(unittest.TestCase):
    def setUp(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.service = SessionService(SQLiteStorage(Path(temp_dir.name) / "sessions.sqlite3"), 720, 10)
        self.session = self.service.issue_session(
            username="alice", add_factors=["password"], metadata={"credential": credential_fingerprint(ALICE)},
        )

    def test_session_with_current_credentials_is_valid(self):
        self.assertTrue(session_is_valid(self.session, RuntimeConfig(users={"alice": ALICE})))

    def test_changed_password_or_totp_ends_the_session(self):
        for changed in (ALICE.model_copy(update={"password_hash": "hash-2"}), ALICE.model_copy(update={"totp_secret": "SECRET-2"})):
            self.assertFalse(session_is_valid(self.session, RuntimeConfig(users={"alice": changed})))

    def test_removed_user_ends_the_session(self):
        self.assertFalse(session_is_valid(self.session, RuntimeConfig(users={})))

    def test_session_without_credential_fingerprint_is_not_valid(self):
        old_session = self.service.issue_session(username="alice", add_factors=["password"])
        self.assertFalse(session_is_valid(old_session, RuntimeConfig(users={"alice": ALICE})))

    def test_revoked_session_is_not_valid(self):
        runtime_config = RuntimeConfig(users={"alice": ALICE}, revoked_sessions={session_id_hash(self.session.session_id)})
        self.assertFalse(session_is_valid(self.session, runtime_config))

    def test_session_without_local_user_only_checks_revocation(self):
        totp_session = self.service.issue_session(add_factors=["totp"])
        self.assertTrue(session_is_valid(totp_session, RuntimeConfig()))

    def test_last_access_is_written_at_most_every_five_minutes(self):
        self.session.metadata["last_seen"] = (datetime.now(UTC) - timedelta(minutes=2)).isoformat()
        recent = self.session.metadata["last_seen"]
        self.service.touch(self.session)
        self.assertEqual(self.service.storage.get_session(self.session.session_id).metadata.get("last_seen"), None)
        self.assertEqual(self.session.metadata["last_seen"], recent)

        self.session.metadata["last_seen"] = (datetime.now(UTC) - timedelta(minutes=6)).isoformat()
        self.service.touch(self.session)
        stored = datetime.fromisoformat(self.service.storage.get_session(self.session.session_id).metadata["last_seen"])
        self.assertLess(datetime.now(UTC) - stored, timedelta(seconds=5))


class SessionSnapshotTests(unittest.TestCase):
    def setUp(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.config_dir = Path(temp_dir.name)
        write_config(self.config_dir, {"alice": ALICE.model_dump()})
        self.storage = SQLiteStorage(self.config_dir / "sessions.sqlite3")
        self.service = SessionService(self.storage, 720, 10)
        self.snapshot_path = self.config_dir / "state" / "sessions.json"
        self.snapshot = SessionSnapshot(self.storage, RuntimeConfigStore(self.config_dir), self.snapshot_path)

    def issue(self, minutes_since_last_access=0):
        return self.service.issue_session(
            username="alice", email="alice@example.test", groups=["staff"], add_factors=["password"],
            metadata={
                "credential": credential_fingerprint(ALICE),
                "host": "app.example.test",
                "client_ip": "203.0.113.5",
                "last_seen": (datetime.now(UTC) - timedelta(minutes=minutes_since_last_access)).isoformat(),
                "oidc_claims": {"name": "Alice"},
            },
        )

    def read(self):
        return json.loads(self.snapshot_path.read_text())["sessions"]

    def test_snapshot_lists_sessions_without_session_id_or_claims(self):
        session = self.issue()
        self.snapshot.refresh()
        content = self.snapshot_path.read_text()
        entry = self.read()[0]
        self.assertEqual(entry["id"], session_id_hash(session.session_id))
        self.assertEqual((entry["username"], entry["host"], entry["client_ip"], entry["online"]), ("alice", "app.example.test", "203.0.113.5", True))
        self.assertNotIn("last_seen", entry)
        self.assertNotIn(session.session_id, content)
        self.assertNotIn("Alice", content)

    def test_session_unused_for_ten_minutes_is_offline_with_last_access(self):
        self.issue(minutes_since_last_access=11)
        self.snapshot.refresh()
        entry = self.read()[0]
        self.assertFalse(entry["online"])
        self.assertIn("last_seen", entry)

    def test_snapshot_is_only_rewritten_when_it_changes(self):
        self.issue()
        self.snapshot.refresh()
        # Nothing changed, so a refresh must not touch the file
        self.snapshot_path.write_text("left untouched")
        self.snapshot.refresh()
        self.assertEqual(self.snapshot_path.read_text(), "left untouched")

        self.issue()
        self.snapshot.refresh()
        self.assertEqual(len(self.read()), 2)

    def test_expired_revoked_and_outdated_sessions_are_removed(self):
        expired = self.service.issue_session(username="alice", add_factors=["password"], expires_in_minutes=1,
                                             metadata={"credential": credential_fingerprint(ALICE)})
        expired.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        self.storage.save_session(expired)
        revoked = self.issue()
        outdated = self.service.issue_session(username="alice", add_factors=["password"], metadata={"credential": "old"})
        kept = self.issue()
        write_config(self.config_dir, {"alice": ALICE.model_dump()}, revoked=[session_id_hash(revoked.session_id)])

        self.snapshot.refresh()
        self.assertEqual([entry["id"] for entry in self.read()], [session_id_hash(kept.session_id)])
        for removed in (expired, revoked, outdated):
            self.assertIsNone(self.storage.get_session(removed.session_id))


if __name__ == "__main__":
    unittest.main()
