"""Sessions of the auth-gateway: published by each gateway, listed and revoked from the WireGuard WebAdmin."""
import ipaddress
import json
import os
import re

from django.utils import timezone
from django.utils.dateparse import parse_datetime

from app_gateway.caddy_config_export import CADDY_EXPORT_DIR
from cluster.models import Worker
from gatekeeper.models import RevokedGatewaySession

PRIMARY_SESSIONS_FILE = os.path.join('state', 'sessions.json')
REVOKED_SESSIONS_FILE = 'revoked_sessions.json'
MAX_REPORTED_SESSIONS = 5000
SESSION_ID_PATTERN = re.compile(r'^[a-f0-9]{64}$')
TEXT_FIELDS = ('username', 'email', 'host', 'client_ip', 'user_agent', 'created_at', 'expires_at', 'last_seen')
LIST_FIELDS = ('groups', 'factors')


def get_export_dir():
    return CADDY_EXPORT_DIR


def clean_gateway_sessions(sessions):
    """Keep only the known fields of the sessions published by a gateway."""
    cleaned = []
    for session in sessions[:MAX_REPORTED_SESSIONS]:
        if not isinstance(session, dict) or not SESSION_ID_PATTERN.match(str(session.get('id', ''))):
            continue
        entry = {'id': session['id'], 'online': session.get('online') is True}
        for field in TEXT_FIELDS:
            if isinstance(session.get(field), str):
                entry[field] = session[field][:254]
        for field in LIST_FIELDS:
            values = session.get(field)
            entry[field] = [str(value)[:64] for value in values[:50]] if isinstance(values, list) else []
        cleaned.append(entry)
    return cleaned


def load_primary_sessions(export_dir=None):
    """Sessions published by the auth-gateway of this primary server, or None when it published none."""
    try:
        with open(os.path.join(export_dir or get_export_dir(), PRIMARY_SESSIONS_FILE), 'r', encoding='utf-8') as sessions_file:
            sessions = json.load(sessions_file).get('sessions')
    except (OSError, ValueError, AttributeError):
        return None
    return clean_gateway_sessions(sessions) if isinstance(sessions, list) else None


def ip_sort_key(value):
    """Value that sorts IP addresses numerically in the sessions table (IPv4, then IPv6, then anything else)."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return f'9-{value}'
    return f'{address.version - 4}-{int(address):039d}'


def _describe(session, server_name, server_key, stale, reported_at, revoked_hashes):
    return dict(
        session,
        server_name=server_name,
        server_key=server_key,
        stale=stale,
        reported_at=reported_at,
        revoking=session['id'] in revoked_hashes,
        created=parse_datetime(session.get('created_at', '')),
        expires=parse_datetime(session.get('expires_at', '')),
        last_seen_at=parse_datetime(session.get('last_seen', '')) if session.get('last_seen') else None,
        client_ip_order=ip_sort_key(session.get('client_ip', '')),
    )


def get_active_sessions(export_dir=None):
    """Sessions of the primary server and of every worker. Worker sessions are the last ones it reported."""
    revoked_hashes = set(RevokedGatewaySession.objects.filter(expires_at__gt=timezone.now()).values_list('session_hash', flat=True))
    rows = [
        _describe(session, None, 'primary', False, None, revoked_hashes)
        for session in load_primary_sessions(export_dir) or []
    ]
    for worker in Worker.objects.select_related('workerstatus').order_by('name'):
        worker_status = getattr(worker, 'workerstatus', None)
        if not worker_status or not worker_status.gateway_sessions:
            continue
        stale = not worker.enabled or not worker_status.is_online
        for session in worker_status.gateway_sessions:
            rows.append(_describe(
                session, worker.display_name, str(worker.uuid), stale, worker_status.gateway_sessions_updated, revoked_hashes,
            ))
    rows.sort(key=lambda row: (not row['online'], row.get('username') or row.get('email') or '', row['server_key']))
    return rows


def build_revoked_sessions_data():
    hashes = RevokedGatewaySession.objects.filter(expires_at__gt=timezone.now()).values_list('session_hash', flat=True)
    return {'sessions': sorted(hashes)}


def write_revoked_sessions(export_dir=None):
    """Publish the revoked sessions to the auth-gateway of this primary server (workers get them by the cluster)."""
    RevokedGatewaySession.objects.filter(expires_at__lte=timezone.now()).delete()
    export_dir = export_dir or get_export_dir()
    if not os.path.isdir(export_dir):
        return
    target = os.path.join(export_dir, REVOKED_SESSIONS_FILE)
    temp_path = f'{target}.tmp'
    with open(temp_path, 'w', encoding='utf-8') as revoked_file:
        json.dump(build_revoked_sessions_data(), revoked_file, indent=2)
        revoked_file.write('\n')
    os.replace(temp_path, target)


def revoke_session(session_hash, export_dir=None):
    """End a session listed by get_active_sessions. Return the revoked session, or None when it is not listed."""
    session = next((row for row in get_active_sessions(export_dir) if row['id'] == session_hash), None)
    if not session or not session['expires']:
        return None
    RevokedGatewaySession.objects.update_or_create(
        session_hash=session_hash,
        defaults={'username': session.get('username') or session.get('email') or '', 'expires_at': session['expires']},
    )
    write_revoked_sessions(export_dir)
    return session
