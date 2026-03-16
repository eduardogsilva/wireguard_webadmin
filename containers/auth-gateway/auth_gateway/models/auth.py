from typing import Annotated, Literal

from pydantic import BaseModel, Field


class IPRuleModel(BaseModel):
    address: str
    prefix_length: int | None = None
    action: Literal["allow", "deny"]
    description: str | None = ""


class TotpMethodModel(BaseModel):
    type: Literal["totp"]
    totp_secret: str | None = None
    session_expiration_minutes: int | None = None


class LocalPasswordMethodModel(BaseModel):
    type: Literal["local_password"]
    session_expiration_minutes: int = 720


class OIDCMethodModel(BaseModel):
    type: Literal["oidc"]
    provider: str
    client_id: str
    client_secret: str
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_emails: list[str] = Field(default_factory=list)
    session_expiration_minutes: int = 720


class IPAddressMethodModel(BaseModel):
    type: Literal["ip_address"]
    rules: list[IPRuleModel] = Field(default_factory=list)


AuthMethodModel = Annotated[
    TotpMethodModel | LocalPasswordMethodModel | OIDCMethodModel | IPAddressMethodModel,
    Field(discriminator="type"),
]


class UserModel(BaseModel):
    email: str | None = ""
    password_hash: str | None = None
    totp_secret: str | None = ""


class GroupModel(BaseModel):
    users: list[str] = Field(default_factory=list)


class PolicyModel(BaseModel):
    policy_type: Literal["bypass", "deny", "protected"]
    groups: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)


class AuthPoliciesFileModel(BaseModel):
    auth_methods: dict[str, AuthMethodModel] = Field(default_factory=dict)
    groups: dict[str, GroupModel] = Field(default_factory=dict)
    users: dict[str, UserModel] = Field(default_factory=dict)
    policies: dict[str, PolicyModel] = Field(default_factory=dict)
