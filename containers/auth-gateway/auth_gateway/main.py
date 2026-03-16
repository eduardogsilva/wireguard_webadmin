from contextlib import asynccontextmanager
from pathlib import Path

from auth_gateway.config_loader import RuntimeConfigStore
from auth_gateway.services.oidc_service import OIDCService
from auth_gateway.services.session_service import SessionService
from auth_gateway.settings import settings
from auth_gateway.storage.sqlite import SQLiteStorage
from auth_gateway.web.auth_routes import router as auth_router
from auth_gateway.web.login_routes import router as login_router
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    storage = SQLiteStorage(settings.database_path)
    app.state.settings = settings
    app.state.config_store = RuntimeConfigStore(settings.config_dir)
    app.state.session_service = SessionService(storage, settings.session_default_minutes, settings.oidc_state_ttl_minutes)
    app.state.oidc_service = OIDCService()
    app.state.templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
    yield


app = FastAPI(title="Auth Gateway", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(auth_router)
app.include_router(login_router)


@app.get("/health")
async def healthcheck():
    return {"status": "ok"}
