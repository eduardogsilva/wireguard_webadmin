import ipaddress
from dataclasses import dataclass, field

from auth_gateway.models.auth import (
    IPAddressMethodModel,
    IPRuleModel,
    LocalPasswordMethodModel,
    OIDCMethodModel,
    PolicyModel,
    TotpMethodModel,
)
from auth_gateway.models.runtime import RuntimeConfig


@dataclass
class EffectivePolicy:
    name: str
    mode: str
    error_message: str | None = None
    required_factors: list[str] = field(default_factory=list)
    allowed_users: set[str] = field(default_factory=set)
    allowed_groups: set[str] = field(default_factory=set)
    ip_method_names: list[str] = field(default_factory=list)
    totp_method_names: list[str] = field(default_factory=list)
    password_method_names: list[str] = field(default_factory=list)
    oidc_method_names: list[str] = field(default_factory=list)
    factor_expirations: dict[str, int] = field(default_factory=dict)


def expand_policy_users(runtime_config: RuntimeConfig, policy: PolicyModel) -> set[str]:
    usernames: set[str] = set()
    for group_name in policy.groups:
        group = runtime_config.groups.get(group_name)
        if group:
            usernames.update(group.users)
    return usernames


def build_effective_policy(runtime_config: RuntimeConfig, policy_name: str) -> EffectivePolicy | None:
    policy = runtime_config.policies.get(policy_name)
    if not policy:
        return None

    effective = EffectivePolicy(
        name=policy_name,
        mode=policy.policy_type,
        error_message=policy.error_message,
        allowed_users=expand_policy_users(runtime_config, policy),
        allowed_groups=set(policy.groups),
    )

    if policy.policy_type != "protected":
        return effective

    if not policy.methods:
        return EffectivePolicy(
            name=policy_name,
            mode="error",
            error_message="Policy configuration error: protected policy has no authentication methods.",
        )

    for method_name in policy.methods:
        method = runtime_config.auth_methods[method_name]
        if isinstance(method, IPAddressMethodModel):
            effective.ip_method_names.append(method_name)
            if "ip" not in effective.required_factors:
                effective.required_factors.append("ip")
        elif isinstance(method, LocalPasswordMethodModel):
            effective.password_method_names.append(method_name)
            effective.required_factors.append("password")
            effective.factor_expirations["password"] = method.session_expiration_minutes
        elif isinstance(method, TotpMethodModel):
            effective.totp_method_names.append(method_name)
            effective.required_factors.append("totp")
            effective.factor_expirations["totp"] = method.session_expiration_minutes or 720
        elif isinstance(method, OIDCMethodModel):
            effective.oidc_method_names.append(method_name)
            effective.required_factors.append("oidc")
            effective.factor_expirations["oidc"] = method.session_expiration_minutes

    return effective


def extract_client_ip(forwarded_for: str) -> str | None:
    if not forwarded_for:
        return None
    candidate = forwarded_for.split(",")[0].strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def evaluate_ip_rules(client_ip: str | None, rules: list[IPRuleModel]) -> bool:
    if not client_ip:
        return False
    ip_value = ipaddress.ip_address(client_ip)
    for rule in rules:
        if rule.prefix_length is None:
            network = ipaddress.ip_network(f"{rule.address}/{'32' if ip_value.version == 4 else '128'}", strict=False)
        else:
            network = ipaddress.ip_network(f"{rule.address}/{rule.prefix_length}", strict=False)
        if ip_value in network:
            return rule.action == "allow"
    return False


def evaluate_ip_access(runtime_config: RuntimeConfig, effective_policy: EffectivePolicy, client_ip: str | None) -> bool:
    if not effective_policy.ip_method_names:
        return True
    for method_name in effective_policy.ip_method_names:
        method = runtime_config.auth_methods[method_name]
        if isinstance(method, IPAddressMethodModel) and evaluate_ip_rules(client_ip, method.rules):
            return True
    return False
