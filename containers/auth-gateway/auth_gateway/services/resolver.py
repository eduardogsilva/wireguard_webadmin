import posixpath
import re
from dataclasses import dataclass
from urllib.parse import unquote

from auth_gateway.models.applications import ApplicationModel
from auth_gateway.models.routes import AppRoutesModel, RoutePolicyBindingModel
from auth_gateway.models.runtime import RuntimeConfig


@dataclass
class RequestContext:
    host: str
    path: str
    application: ApplicationModel
    route: RoutePolicyBindingModel | None
    policy_name: str


def normalize_host(raw_host: str) -> str:
    return raw_host.split(":", 1)[0].strip().lower()


def normalize_path(raw_uri: str) -> str:
    """
    Path used to pick the policy, normalized the same way Caddy matches routes: repeated slashes are merged and
    . and .. segments are resolved. The value is a request URI, never a full URL, so a leading // is part of the
    path and not a network location.
    """
    path = re.split(r"[?#]", raw_uri or "/", maxsplit=1)[0]
    path = unquote(path) or "/"
    path = path if path.startswith("/") else f"/{path}"
    path = re.sub(r"/{2,}", "/", path)
    return posixpath.normpath(path)


def _path_matches(path: str, prefix: str) -> bool:
    """Check path boundary correctly — prevents /admin matching /administrator. Case-insensitive, like Caddy."""
    path = path.lower()
    prefix = prefix.rstrip("/").lower()
    return path == prefix or path.startswith(prefix + "/")


def resolve_application(runtime_config: RuntimeConfig, host: str) -> ApplicationModel | None:
    normalized_host = normalize_host(host)
    for application in runtime_config.applications.values():
        if normalized_host in {candidate.lower() for candidate in application.hosts}:
            return application
    return None


def resolve_route(runtime_config: RuntimeConfig, application_id: str, path: str) -> tuple[RoutePolicyBindingModel | None, str | None]:
    app_routes: AppRoutesModel | None = runtime_config.routes_by_app.get(application_id)
    if not app_routes:
        return None, None

    normalized_path = normalize_path(path)
    sorted_routes = sorted(app_routes.routes, key=lambda route: len(route.path_prefix), reverse=True)
    for route in sorted_routes:
        route_prefix = normalize_path(route.path_prefix)
        if _path_matches(normalized_path, route_prefix):
            return route, route.policy
    return None, app_routes.default_policy


def resolve_request_context(runtime_config: RuntimeConfig, host: str, path: str) -> RequestContext | None:
    application = resolve_application(runtime_config, host)
    if not application:
        return None
    route, policy_name = resolve_route(runtime_config, application.id, path)
    if not policy_name:
        return None
    return RequestContext(
        host=normalize_host(host),
        path=normalize_path(path),
        application=application,
        route=route,
        policy_name=policy_name,
    )
