from pathlib import Path
from secrets import token_hex

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTH_GATEWAY_", extra="ignore")

    config_dir: Path = Field(default=Path("/caddy_json_export"))
    database_path: Path = Field(default=Path("/data/auth-gateway.sqlite3"))
    cookie_name: str = Field(default="auth_gateway_session")
    csrf_cookie_name: str = Field(default="auth_gateway_csrf")
    external_path: str = Field(default="/auth-gateway")
    secure_cookies: bool = Field(default=True)
    session_default_minutes: int = Field(default=720)
    oidc_state_ttl_minutes: int = Field(default=10)
    challenge_secret: str = Field(default_factory=lambda: token_hex(32))


settings = Settings()
