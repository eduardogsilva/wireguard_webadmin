import socket
import ssl
import subprocess
from datetime import datetime, timezone

# Caddy shares the network namespace of the WireGuard WebAdmin container
CADDY_TLS_ADDRESS = ('127.0.0.1', 443)
CONNECTION_TIMEOUT = 3
INTERNAL_CA_NAME = 'Caddy Local Authority'


def _parse_not_after(value):
    return datetime.strptime(value, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)


def _issuer_name(issuer_fields):
    issuer = dict(field[0] for field in issuer_fields)
    return issuer.get('organizationName') or issuer.get('commonName') or ''


def _fetch_certificate(hostname, verify):
    if verify:
        context = ssl.create_default_context()
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    with socket.create_connection(CADDY_TLS_ADDRESS, timeout=CONNECTION_TIMEOUT) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
            if verify:
                return tls_socket.getpeercert()
            return tls_socket.getpeercert(binary_form=True)


def _describe_untrusted_certificate(certificate_der):
    result = subprocess.run(
        ['openssl', 'x509', '-inform', 'DER', '-noout', '-issuer', '-enddate', '-nameopt', 'RFC2253'],
        input=certificate_der, capture_output=True, timeout=CONNECTION_TIMEOUT,
    )
    issuer = ''
    not_after = None
    for line in result.stdout.decode(errors='replace').splitlines():
        if line.startswith('issuer='):
            issuer_parts = dict(
                part.split('=', 1) for part in line[len('issuer='):].split(',') if '=' in part
            )
            issuer = issuer_parts.get('O') or issuer_parts.get('CN') or ''
            if INTERNAL_CA_NAME in line:
                issuer = INTERNAL_CA_NAME
        elif line.startswith('notAfter='):
            not_after = _parse_not_after(line[len('notAfter='):])
    return issuer, not_after


def inspect_certificate(hostname):
    """
    Return the status of the certificate Caddy serves for a hostname:
    'trusted', 'untrusted' (served but not trusted, e.g. internal CA) or 'unavailable'.
    """
    try:
        certificate = _fetch_certificate(hostname, verify=True)
        return {
            'status': 'trusted',
            'issuer': _issuer_name(certificate.get('issuer', ())),
            'not_after': _parse_not_after(certificate['notAfter']),
        }
    except ssl.SSLCertVerificationError:
        pass
    except (OSError, ValueError):
        return {'status': 'unavailable', 'issuer': '', 'not_after': None}

    try:
        certificate_der = _fetch_certificate(hostname, verify=False)
        issuer, not_after = _describe_untrusted_certificate(certificate_der)
    except (OSError, ValueError, subprocess.SubprocessError):
        return {'status': 'unavailable', 'issuer': '', 'not_after': None}
    return {'status': 'untrusted', 'issuer': issuer, 'not_after': not_after}
