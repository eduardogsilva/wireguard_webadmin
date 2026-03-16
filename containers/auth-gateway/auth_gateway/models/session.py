from datetime import datetime

from pydantic import BaseModel, Field


class SessionRecord(BaseModel):
    session_id: str
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    username: str | None = None
    email: str | None = None
    subject: str | None = None
    groups: list[str] = Field(default_factory=list)
    auth_factors: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class OIDCStateRecord(BaseModel):
    state: str
    nonce: str
    method_name: str
    host: str
    next_url: str
    created_at: datetime
    expires_at: datetime
