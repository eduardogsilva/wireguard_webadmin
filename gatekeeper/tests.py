import json
import os
import tempfile
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cluster.models import Worker, WorkerStatus
from cluster.sync import build_gateway_section
from gatekeeper.models import RevokedGatewaySession
from gatekeeper.sessions import (
    REVOKED_SESSIONS_FILE,
    build_revoked_sessions_data,
    clean_gateway_sessions,
    get_active_sessions,
)
from user_manager.models import UserAcl

PRIMARY_ID = 'a' * 64
WORKER_ID = 'b' * 64


def gateway_session(session_id, username='alice', online=True, expires_in_hours=6):
    session = {
        'id': session_id,
        'username': username,
        'email': f'{username}@example.test',
        'groups': ['staff'],
        'factors': ['password'],
        'host': 'app.example.test',
        'client_ip': '203.0.113.5',
        'user_agent': 'test',
        'created_at': timezone.now().isoformat(),
        'expires_at': (timezone.now() + timedelta(hours=expires_in_hours)).isoformat(),
        'online': online,
    }
    if not online:
        session['last_seen'] = (timezone.now() - timedelta(minutes=30)).isoformat()
    return session


class GatewaySessionsTestMixin:
    """Primary server sessions in a temporary export directory and one worker reporting its sessions."""

    def setUp(self):
        super().setUp()
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.export_dir = temp_dir.name
        patcher = patch('gatekeeper.sessions.CADDY_EXPORT_DIR', self.export_dir)
        patcher.start()
        self.addCleanup(patcher.stop)

        os.makedirs(os.path.join(self.export_dir, 'state'))
        with open(os.path.join(self.export_dir, 'state', 'sessions.json'), 'w', encoding='utf-8') as sessions_file:
            json.dump({'sessions': [gateway_session(PRIMARY_ID)]}, sessions_file)

        self.worker = Worker.objects.create(name='node-a', hostname='node-a.example.test')
        WorkerStatus.objects.create(
            worker=self.worker, gateway_sessions=[gateway_session(WORKER_ID, username='bob', online=False)],
            gateway_sessions_updated=timezone.now(),
        )

    def read_revoked_file(self):
        with open(os.path.join(self.export_dir, REVOKED_SESSIONS_FILE), 'r', encoding='utf-8') as revoked_file:
            return json.load(revoked_file)['sessions']


class GatewaySessionDataTests(GatewaySessionsTestMixin, TestCase):
    def test_reported_sessions_keep_only_known_fields(self):
        cleaned = clean_gateway_sessions([
            dict(gateway_session(PRIMARY_ID), session_id='secret', extra='x', groups=['g'] * 80),
            {'id': 'not-a-hash', 'username': 'mallory'},
            'not a session',
        ])
        self.assertEqual(len(cleaned), 1)
        self.assertNotIn('session_id', cleaned[0])
        self.assertNotIn('extra', cleaned[0])
        self.assertEqual(len(cleaned[0]['groups']), 50)

    def test_active_sessions_list_primary_and_workers(self):
        sessions = {session['id']: session for session in get_active_sessions()}
        self.assertEqual(set(sessions), {PRIMARY_ID, WORKER_ID})
        self.assertIsNone(sessions[PRIMARY_ID]['server_name'])
        self.assertEqual(sessions[WORKER_ID]['server_name'], self.worker.display_name)
        self.assertFalse(sessions[WORKER_ID]['online'])
        self.assertIsNotNone(sessions[WORKER_ID]['last_seen_at'])

    def test_sessions_of_offline_workers_are_marked(self):
        WorkerStatus.objects.filter(worker=self.worker).update(last_seen=timezone.now() - timedelta(minutes=20))
        sessions = {session['id']: session for session in get_active_sessions()}
        self.assertTrue(sessions[WORKER_ID]['stale'])
        self.assertFalse(sessions[PRIMARY_ID]['stale'])

    def test_revoked_sessions_only_list_sessions_not_expired(self):
        RevokedGatewaySession.objects.create(session_hash=PRIMARY_ID, expires_at=timezone.now() + timedelta(hours=1))
        RevokedGatewaySession.objects.create(session_hash=WORKER_ID, expires_at=timezone.now() - timedelta(hours=1))
        self.assertEqual(build_revoked_sessions_data(), {'sessions': [PRIMARY_ID]})

    def test_gateway_section_carries_revoked_sessions_to_workers(self):
        RevokedGatewaySession.objects.create(session_hash=WORKER_ID, expires_at=timezone.now() + timedelta(hours=1))
        section = build_gateway_section(self.worker)
        self.assertEqual(json.loads(section.files[REVOKED_SESSIONS_FILE])['sessions'], [WORKER_ID])


class RevokeSessionViewTests(GatewaySessionsTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.admin = User.objects.create_user(username='admin', password='unused')
        UserAcl.objects.create(user=self.admin, user_level=50)
        self.client.force_login(self.admin)

    def test_revoking_a_worker_session_publishes_it(self):
        response = self.client.post('/gatekeeper/session/revoke/', {'session': WORKER_ID})
        self.assertRedirects(response, '/gatekeeper/?tab=sessions', fetch_redirect_response=False)
        revoked = RevokedGatewaySession.objects.get(session_hash=WORKER_ID)
        self.assertEqual(revoked.username, 'bob')
        self.assertEqual(self.read_revoked_file(), [WORKER_ID])
        self.assertTrue(next(session for session in get_active_sessions() if session['id'] == WORKER_ID)['revoking'])

    def test_unknown_session_is_not_revoked(self):
        self.client.post('/gatekeeper/session/revoke/', {'session': 'c' * 64})
        self.assertFalse(RevokedGatewaySession.objects.exists())

    def test_revoke_requires_post(self):
        self.assertEqual(self.client.get('/gatekeeper/session/revoke/', {'session': WORKER_ID}).status_code, 405)
        self.assertFalse(RevokedGatewaySession.objects.exists())

    def test_revoke_requires_level_50(self):
        UserAcl.objects.filter(user=self.admin).update(user_level=40)
        self.client.post('/gatekeeper/session/revoke/', {'session': WORKER_ID})
        self.assertFalse(RevokedGatewaySession.objects.exists())

    def test_sessions_tab_lists_sessions(self):
        UserAcl.objects.filter(user=self.admin).update(user_level=20)
        content = self.client.get('/gatekeeper/?tab=sessions').content.decode()
        self.assertIn('alice@example.test', content)
        self.assertIn('bob@example.test', content)
