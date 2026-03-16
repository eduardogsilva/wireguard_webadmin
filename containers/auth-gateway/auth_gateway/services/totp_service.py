import pyotp


def verify_totp(secret: str, token: str) -> bool:
    normalized_secret = secret.strip()
    normalized_token = token.strip().replace(" ", "")
    if not normalized_secret or not normalized_token:
        return False
    return pyotp.TOTP(normalized_secret).verify(normalized_token, valid_window=1)
