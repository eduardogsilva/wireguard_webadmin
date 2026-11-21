import ipaddress

from fastapi import Request
from slowapi import Limiter

AUTH_RATE_LIMIT = "5/minute"


def _is_trusted_proxy(peer: str) -> bool:
    """Caddy reaches the gateway over a Docker network, so only private and loopback peers can forward the client."""
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return address.is_private or address.is_loopback


def get_real_client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for and _is_trusted_proxy(peer):
        return forwarded_for.split(",")[0].strip()
    return peer or "unknown"


def get_rate_limit_key(request: Request) -> str:
    """Client address used by the rate limit. IPv6 clients usually own a whole /64, so it counts as one address."""
    client = get_real_client_ip(request)
    try:
        address = ipaddress.ip_address(client)
    except ValueError:
        return client
    if address.version == 6:
        if address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return str(address)


limiter = Limiter(key_func=get_rate_limit_key)
