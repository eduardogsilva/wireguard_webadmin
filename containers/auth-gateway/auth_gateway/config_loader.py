import json
import logging
from pathlib import Path
from urllib.parse import urlparse

from auth_gateway.models.applications import ApplicationsFileModel
from auth_gateway.models.auth import AuthPoliciesFileModel, OIDCMethodModel, PolicyModel
from auth_gateway.models.routes import RoutesFileModel
from auth_gateway.models.runtime import RuntimeConfig

logger = logging.getLogger(__name__)


def _load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _is_valid_provider_url(method_name: str, method: OIDCMethodModel) -> bool:
    if not method.provider:
        logger.warning("OIDC method '%s' has no provider URL configured — it will be unavailable.", method_name)
        return False
    parsed = urlparse(method.provider)
    hostname = parsed.hostname or ""
    if parsed.scheme not in {"http", "https"} or not hostname or ".." in hostname:
        logger.warning("OIDC method '%s' has an invalid provider URL ('%s') — it will be unavailable.", method_name, method.provider)
        return False
    return True


def _load_applications(config_dir: Path) -> dict:
    combined = {}
    for filename in ("wireguard_webadmin.json", "applications.json"):
        payload = _load_json(config_dir / filename)
        if not payload:
            continue
        parsed = ApplicationsFileModel.model_validate(payload)
        for entry in parsed.entries:
            if entry.id in combined:
                raise ValueError(f"Duplicate application id detected: '{entry.id}'.")
            combined[entry.id] = entry
    return combined


def load_runtime_config(config_dir: Path) -> RuntimeConfig:
    applications = _load_applications(config_dir)

    routes_payload = _load_json(config_dir / "routes.json") or {}
    auth_payload = _load_json(config_dir / "auth_policies.json") or {}

    routes = RoutesFileModel.model_validate(routes_payload)
    auth = AuthPoliciesFileModel.model_validate(auth_payload)

    valid_auth_methods = {}
    for method_name, method in auth.auth_methods.items():
        if isinstance(method, OIDCMethodModel) and not _is_valid_provider_url(method_name, method):
            continue
        valid_auth_methods[method_name] = method
    auth.auth_methods = valid_auth_methods

    for app_id in routes.entries:
        if app_id not in applications:
            raise ValueError(f"Routes reference unknown application '{app_id}'.")

    for app_id, route_config in routes.entries.items():
        if route_config.default_policy and route_config.default_policy not in auth.policies:
            raise ValueError(f"Application '{app_id}' references unknown default policy '{route_config.default_policy}'.")
        for route in route_config.routes:
            if route.policy not in auth.policies:
                raise ValueError(f"Application '{app_id}' route '{route.path_prefix}' references unknown policy '{route.policy}'.")

    for policy_name, policy in auth.policies.items():
        for group_name in policy.groups:
            if group_name not in auth.groups:
                raise ValueError(f"Policy '{policy_name}' references unknown group '{group_name}'.")
        for method_name in policy.methods:
            if method_name not in auth.auth_methods:
                logger.warning(
                    "Policy '%s' references unavailable method '%s' — policy forced to deny.",
                    policy_name, method_name,
                )
                auth.policies[policy_name] = PolicyModel(policy_type="deny")
                break

    return RuntimeConfig(
        applications=applications,
        routes_by_app=routes.entries,
        auth_methods=auth.auth_methods,
        users=auth.users,
        groups=auth.groups,
        policies=auth.policies,
    )


class RuntimeConfigStore:
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self._runtime_config: RuntimeConfig | None = None
        self._mtimes: dict[str, int] = {}

    def _current_mtimes(self) -> dict[str, int]:
        mtimes = {}
        for filename in (
            "wireguard_webadmin.json",
            "applications.json",
            "routes.json",
            "auth_policies.json",
        ):
            path = self.config_dir / filename
            if path.exists():
                mtimes[filename] = path.stat().st_mtime_ns
        return mtimes

    def get(self) -> RuntimeConfig:
        current_mtimes = self._current_mtimes()
        if self._runtime_config is None or current_mtimes != self._mtimes:
            self._runtime_config = load_runtime_config(self.config_dir)
            self._mtimes = current_mtimes
        return self._runtime_config
