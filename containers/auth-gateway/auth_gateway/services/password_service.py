from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from auth_gateway.models.auth import UserModel


password_hasher = PasswordHasher()


MAX_PASSWORD_LENGTH = 1024


def verify_user_password(username: str, password: str, users: dict[str, UserModel]) -> UserModel | None:
    if not password or len(password) > MAX_PASSWORD_LENGTH:
        return None
    user = users.get(username)
    if not user or not user.password_hash:
        return None
    try:
        password_hasher.verify(user.password_hash, password)
    except VerifyMismatchError:
        return None
    return user
