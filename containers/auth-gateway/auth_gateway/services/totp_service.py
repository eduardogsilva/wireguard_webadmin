import hashlib
import logging
import time
from datetime import datetime

import pyotp

logger = logging.getLogger("uvicorn.error")

VALID_WINDOW = 1
# (secret hash, time step) of codes already accepted, so a code cannot be used twice
_used_codes: dict[tuple[str, int], float] = {}


def _forget_expired_codes(now: float, interval: int) -> None:
    oldest = now - interval * (2 * VALID_WINDOW + 2)
    for key, used_at in list(_used_codes.items()):
        if used_at < oldest:
            del _used_codes[key]


def verify_totp(secret: str, token: str) -> bool:
    normalized_secret = secret.strip()
    normalized_token = token.strip().replace(" ", "")
    if not normalized_secret or not normalized_token:
        return False
    try:
        totp = pyotp.TOTP(normalized_secret)
    except ValueError as error:
        logger.warning("TOTP secret rejected (%s) — generate a new secret with at least 24 Base32 characters.", error)
        return False

    now = time.time()
    _forget_expired_codes(now, totp.interval)
    secret_hash = hashlib.sha256(normalized_secret.encode()).hexdigest()
    current_step = totp.timecode(datetime.fromtimestamp(now))
    for offset in range(-VALID_WINDOW, VALID_WINDOW + 1):
        step = current_step + offset
        if pyotp.utils.strings_equal(normalized_token, totp.generate_otp(step)):
            if (secret_hash, step) in _used_codes:
                logger.warning("TOTP code reuse rejected.")
                return False
            _used_codes[(secret_hash, step)] = now
            return True
    return False
