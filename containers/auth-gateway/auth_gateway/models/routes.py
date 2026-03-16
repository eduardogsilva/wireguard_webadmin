from pydantic import BaseModel, Field


class RoutePolicyBindingModel(BaseModel):
    id: str | None = None
    path_prefix: str
    policy: str


class AppRoutesModel(BaseModel):
    routes: list[RoutePolicyBindingModel] = Field(default_factory=list)
    default_policy: str | None = None


class RoutesFileModel(BaseModel):
    entries: dict[str, AppRoutesModel] = Field(default_factory=dict)
