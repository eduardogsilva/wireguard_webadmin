from urllib.parse import urlencode

from auth_gateway.config_loader import RuntimeConfigStore
from auth_gateway.models.auth import OIDCMethodModel, TotpMethodModel
from auth_gateway.models.runtime import RuntimeConfig
from auth_gateway.models.session import SessionRecord
from auth_gateway.services.policy_engine import EffectivePolicy, build_effective_policy
from auth_gateway.services.resolver import RequestContext, normalize_host, normalize_path, resolve_request_context
from fastapi import HTTPException, Request


def get_runtime_config(request: Request) -> RuntimeConfig:
    store: RuntimeConfigStore = request.app.state.config_store
    return store.get()


def get_session(request: Request) -> SessionRecord | None:
    session_service = request.app.state.session_service
    cookie_name = request.app.state.settings.cookie_name
    return session_service.get_session(request.cookies.get(cookie_name))


def build_external_url(request: Request, path: str, **params: str) -> str:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
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
