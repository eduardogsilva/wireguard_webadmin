import base64
import hashlib
import hmac
import json
import os
import time

ALTCHA_MAX_NUMBER = 1_000_000
CHALLENGE_TTL_SECONDS = 300  # 5 minutes
CHALLENGE_COOKIE_NAME = "auth_gateway_challenge"


def generate_altcha_challenge(hmac_key: str) -> dict:
    salt = os.urandom(12).hex()
    number = int.from_bytes(os.urandom(4), "big") % ALTCHA_MAX_NUMBER
    challenge = hashlib.sha256(f"{salt}{number}".encode()).hexdigest()
    signature = hmac.new(hmac_key.encode(), challenge.encode(), hashlib.sha256).hexdigest()
    return {
        "algorithm": "SHA-256",
        "challenge": challenge,
        "salt": salt,
        "signature": signature,
        "maxnumber": ALTCHA_MAX_NUMBER,
    }


def verify_altcha_solution(payload_b64: str, hmac_key: str) -> bool:
    try:
        padding = (4 - len(payload_b64) % 4) % 4
        data = base64.b64decode(payload_b64 + "=" * padding)
        payload = json.loads(data.decode())
        algorithm = payload.get("algorithm", "")
        challenge = payload.get("challenge", "")
        salt = payload.get("salt", "")
        number = payload.get("number")
        signature = payload.get("signature", "")
        if algorithm != "SHA-256" or not all([challenge, salt, signature, number is not None]):
            return False
        expected_sig = hmac.new(hmac_key.encode(), challenge.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, signature):
            return False
        computed = hashlib.sha256(f"{salt}{number}".encode()).hexdigest()
        return hmac.compare_digest(computed, challenge)
    except Exception:
        return False


def generate_challenge_cookie(secret: str) -> str:
    timestamp = str(int(time.time()))
    nonce = os.urandom(8).hex()
    message = f"{timestamp}.{nonce}"
    sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return f"{message}.{sig}"


def verify_challenge_cookie(cookie_value: str, secret: str) -> bool:
    try:
        last_dot = cookie_value.rfind(".")
        if last_dot == -1:
            return False
        message = cookie_value[:last_dot]
        sig = cookie_value[last_dot + 1:]
        expected_sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, sig):
            return False
        timestamp = int(message.split(".")[0])
        return (time.time() - timestamp) < CHALLENGE_TTL_SECONDS
    except Exception:
        return False
