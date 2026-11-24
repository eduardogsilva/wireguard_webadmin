from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from auth_gateway.models.auth import UserModel

password_hasher = PasswordHasher()
# Checked when the user does not exist, so the response time does not reveal which usernames exist
DUMMY_PASSWORD_HASH = password_hasher.hash("unused-password")


MAX_PASSWORD_LENGTH = 1024


def verify_user_password(username: str, password: str, users: dict[str, UserModel]) -> UserModel | None:
    if not password or len(password) > MAX_PASSWORD_LENGTH:
        return None
    user = users.get(username)
    password_hash = user.password_hash if user and user.password_hash else DUMMY_PASSWORD_HASH
    try:
        password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return None
    return user if password_hash is not DUMMY_PASSWORD_HASH else None
