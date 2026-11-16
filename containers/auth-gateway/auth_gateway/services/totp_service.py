import logging

import pyotp

logger = logging.getLogger("uvicorn.error")


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
    return totp.verify(normalized_token, valid_window=1)
