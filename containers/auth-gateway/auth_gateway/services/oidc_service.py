from dataclasses import dataclass

from auth_gateway.models.auth import OIDCMethodModel
from authlib.integrations.starlette_client import OAuth


@dataclass
class OIDCIdentity:
    subject: str | None
    email: str | None
    claims: dict


class OIDCService:
    def __init__(self):
        self.oauth = OAuth()
        self._clients = {}

    def _client(self, method_name: str, method: OIDCMethodModel):
        if method_name in self._clients:
            return self._clients[method_name]
        metadata_url = f"{method.provider.rstrip('/')}/.well-known/openid-configuration"
        client = self.oauth.register(
            name=f"oidc_{method_name}",
            client_id=method.client_id,
            client_secret=method.client_secret,
            server_metadata_url=metadata_url,
            client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"},
        )
        self._clients[method_name] = client
        return client

    async def build_authorization_redirect(self, request, method_name: str, method: OIDCMethodModel, redirect_uri: str, state: str, nonce: str):
        client = self._client(method_name, method)
        return await client.authorize_redirect(request, redirect_uri, state=state, nonce=nonce)

    async def finish_callback(self, request, method_name: str, method: OIDCMethodModel, nonce: str) -> OIDCIdentity:
        client = self._client(method_name, method)
        token = await client.authorize_access_token(request)
        claims = {}
        if "userinfo" in token and isinstance(token["userinfo"], dict):
            claims = token["userinfo"]
        elif "id_token" in token:
            claims = await client.parse_id_token(request, token, nonce=nonce)
        email = claims.get("email")
        subject = claims.get("sub")
        return OIDCIdentity(subject=subject, email=email, claims=dict(claims))


def is_oidc_identity_allowed(method: OIDCMethodModel, email: str | None) -> bool:
    if not email:
        return not method.allowed_domains and not method.allowed_emails
    normalized_email = email.lower()
    normalized_domain = normalized_email.split("@", 1)[1] if "@" in normalized_email else ""
    allowed_emails = {item.lower() for item in method.allowed_emails}
    allowed_domains = {item.lower() for item in method.allowed_domains}
    if not allowed_emails and not allowed_domains:
        return True
    return normalized_email in allowed_emails or normalized_domain in allowed_domains
