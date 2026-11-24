from pydantic import BaseModel, Field

from auth_gateway.models.applications import ApplicationModel
from auth_gateway.models.auth import AuthMethodModel, GroupModel, PolicyModel, UserModel
from auth_gateway.models.routes import AppRoutesModel


class RuntimeConfig(BaseModel):
    applications: dict[str, ApplicationModel] = Field(default_factory=dict)
    routes_by_app: dict[str, AppRoutesModel] = Field(default_factory=dict)
    auth_methods: dict[str, AuthMethodModel] = Field(default_factory=dict)
    users: dict[str, UserModel] = Field(default_factory=dict)
    groups: dict[str, GroupModel] = Field(default_factory=dict)
    policies: dict[str, PolicyModel] = Field(default_factory=dict)
    # sha256 of the IDs of sessions ended from the WireGuard WebAdmin
    revoked_sessions: set[str] = Field(default_factory=set)
