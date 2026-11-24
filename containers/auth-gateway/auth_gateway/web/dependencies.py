from datetime import UTC, datetime
from secrets import token_urlsafe
from urllib.parse import urlencode

from fastapi import HTTPException, Request
from fastapi.responses import Response

from auth_gateway.config_loader import RuntimeConfigStore
from auth_gateway.limiter import get_real_client_ip
from auth_gateway.models.auth import OIDCMethodModel, TotpMethodModel
from auth_gateway.models.runtime import RuntimeConfig
from auth_gateway.models.session import SessionRecord
from auth_gateway.services.policy_engine import EffectivePolicy, build_effective_policy
from auth_gateway.services.resolver import RequestContext, normalize_host, normalize_path, resolve_request_context
from auth_gateway.services.session_service import credential_fingerprint, session_is_valid


def get_runtime_config(request: Request) -> RuntimeConfig:
    store: RuntimeConfigStore = request.app.state.config_store
    return store.get()


def get_session(request: Request) -> SessionRecord | None:
    session_service = request.app.state.session_service
    cookie_name = request.app.state.settings.cookie_name
    session = session_service.get_session(request.cookies.get(cookie_name))
    if session and not session_is_valid(session, get_runtime_config(request)):
        session_service.delete_session(session.session_id)
        return None
    return session


def login_metadata(request: Request, username: str | None = None) -> dict:
    """Where the session was opened and, for local users, the fingerprint of their credentials."""
    metadata = {
        "host": normalize_host(request.headers.get("host", "")),
        "client_ip": get_real_client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:200],
        "last_seen": datetime.now(UTC).isoformat(),
    }
    user = get_runtime_config(request).users.get(username) if username else None
    if user:
        metadata["credential"] = credential_fingerprint(user)
    return metadata


def build_external_url(request: Request, path: str, **params: str) -> str:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    if proto not in ("http", "https"):
        proto = "https"
    host = request.headers.get("host", request.url.netloc)
    prefix = request.app.state.settings.external_path.rstrip("/")
    query = urlencode({key: value for key, value in params.items() if value is not None})
    base = f"{proto}://{host}{prefix}{path}"
    return f"{base}?{query}" if query else base


def normalize_next_path(next_url: str | None) -> str:
    if not next_url:
        return "/"
    normalized = normalize_path(next_url)
    return normalized


def resolve_context_from_request(request: Request, runtime_config: RuntimeConfig, next_url: str | None = None) -> RequestContext:
    host = normalize_host(request.headers.get("host", request.url.hostname or ""))
    path = normalize_next_path(next_url)
    context = resolve_request_context(runtime_config, host, path)
    if not context:
        raise HTTPException(status_code=403, detail="No matching application or policy.")
    return context


def get_effective_policy(runtime_config: RuntimeConfig, policy_name: str) -> EffectivePolicy:
    effective_policy = build_effective_policy(runtime_config, policy_name)
    if not effective_policy:
        raise HTTPException(status_code=403, detail="Referenced policy was not found.")
    return effective_policy


def session_is_allowed(session: SessionRecord | None, effective_policy: EffectivePolicy) -> bool:
    if not effective_policy.allowed_users:
        return True
    if not session or not session.username:
        return False
    return session.username in effective_policy.allowed_users


def get_session_factors(session: SessionRecord | None, effective_policy: EffectivePolicy) -> set[str]:
    """
    Factors of the session that count for the policy. OIDC and TOTP only count when they were completed with one
    of the methods of the policy: each method has its own allowlists or secret.
    """
    if not session:
        return set()
    factors = set(session.auth_factors)
    factor_methods = session.metadata.get("factor_methods", {})
    for factor, method_names in (("oidc", effective_policy.oidc_method_names), ("totp", effective_policy.totp_method_names)):
        if factor in factors and not set(factor_methods.get(factor, [])) & set(method_names):
            factors.discard(factor)
    return factors


def factor_method_metadata(session: SessionRecord | None, factor: str, method_name: str) -> dict:
    """Session metadata recording that the factor was completed with the given method."""
    current = session.metadata.get("factor_methods", {}) if session else {}
    factor_methods = {name: list(methods) for name, methods in current.items()}
    method_names = factor_methods.setdefault(factor, [])
    if method_name not in method_names:
        method_names.append(method_name)
    return {"factor_methods": factor_methods}


def get_totp_method(runtime_config: RuntimeConfig, effective_policy: EffectivePolicy) -> tuple[str, TotpMethodModel] | tuple[None, None]:
    for method_name in effective_policy.totp_method_names:
        method = runtime_config.auth_methods[method_name]
        if isinstance(method, TotpMethodModel):
            return method_name, method
    return None, None


def get_oidc_method(runtime_config: RuntimeConfig, effective_policy: EffectivePolicy) -> tuple[str, OIDCMethodModel] | tuple[None, None]:
    for method_name in effective_policy.oidc_method_names:
        method = runtime_config.auth_methods[method_name]
        if isinstance(method, OIDCMethodModel):
            return method_name, method
    return None, None


def get_effective_expiration(request: Request, effective_policy: EffectivePolicy, factors: list[str]) -> int:
    settings = request.app.state.settings
    expirations = [effective_policy.factor_expirations.get(factor) for factor in factors if effective_policy.factor_expirations.get(factor)]
    return min(expirations) if expirations else settings.session_default_minutes


def get_or_create_csrf_token(request: Request) -> str:
    cookie_name = request.app.state.settings.csrf_cookie_name
    existing_token = request.cookies.get(cookie_name)
    if existing_token:
        return existing_token
    return token_urlsafe(32)


def set_csrf_cookie(request: Request, response: Response, csrf_token: str) -> None:
    response.set_cookie(
        key=request.app.state.settings.csrf_cookie_name,
        value=csrf_token,
        httponly=False,
        secure=request.app.state.settings.secure_cookies,
        samesite="strict",
        path="/",
    )


def validate_csrf(request: Request, submitted_token: str | None) -> None:
    cookie_name = request.app.state.settings.csrf_cookie_name
    cookie_token = request.cookies.get(cookie_name)
    if not cookie_token or not submitted_token or cookie_token != submitted_token:
        raise HTTPException(status_code=403, detail="CSRF validation failed.")


def challenge_is_valid(request: Request) -> bool:
    from auth_gateway.services.challenge_service import CHALLENGE_COOKIE_NAME, verify_challenge_cookie
    cookie = request.cookies.get(CHALLENGE_COOKIE_NAME)
    if not cookie:
        return False
    return verify_challenge_cookie(cookie, request.app.state.settings.challenge_secret)


def build_challenge_url(request: Request, login_route: str, next_url: str, error: str | None = None) -> str:
    external_path = request.app.state.settings.external_path.rstrip("/")
    login_path = f"{external_path}{login_route}"
    params = {}
    if next_url and next_url != "/":
        params["next"] = next_url
    if error:
        params["error"] = error
    if params:
        login_path = f"{login_path}?{urlencode(params)}"
    return build_external_url(request, "/challenge", next=login_path)
