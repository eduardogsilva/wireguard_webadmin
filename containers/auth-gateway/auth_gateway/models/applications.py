from pydantic import BaseModel, Field


class StaticRouteModel(BaseModel):
    path_prefix: str
    root: str
    strip_prefix: str | None = None
    cache_control: str | None = None


class ApplicationModel(BaseModel):
    id: str
    name: str
    hosts: list[str] = Field(default_factory=list)
    upstream: str
    static_routes: list[StaticRouteModel] = Field(default_factory=list)


class ApplicationsFileModel(BaseModel):
    entries: list[ApplicationModel] = Field(default_factory=list)
