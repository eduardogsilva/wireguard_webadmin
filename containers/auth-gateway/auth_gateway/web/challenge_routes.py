from urllib.parse import urlsplit

from auth_gateway.services.challenge_service import (
    CHALLENGE_COOKIE_NAME,
    generate_altcha_challenge,
    generate_challenge_cookie,
    verify_altcha_solution,
)
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

router = APIRouter()


def _safe_next(url: str | None, external_path: str) -> str:
    if not url:
        return f"{external_path}/login"
    parts = urlsplit(url)
    if parts.scheme or parts.netloc:
        return f"{external_path}/login"
    path = parts.path or "/"
    if not path.startswith("/"):
        return f"{external_path}/login"
    return f"{path}?{parts.query}" if parts.query else path


@router.get("/challenge", response_class=HTMLResponse)
async def challenge_page(request: Request, next: str = "/"):
    external_path = request.app.state.settings.external_path
    return request.app.state.templates.TemplateResponse(
        "challenge.html",
        {"request": request, "external_path": external_path, "next": next},
    )


@router.get("/challenge/data")
async def challenge_data(request: Request):
    hmac_key = request.app.state.settings.challenge_secret
    challenge = generate_altcha_challenge(hmac_key)
    return JSONResponse(challenge)


@router.post("/challenge/verify")
async def challenge_verify(request: Request, next: str = Form("/"), altcha: str = Form(...)):
    hmac_key = request.app.state.settings.challenge_secret
    external_path = request.app.state.settings.external_path

    if not verify_altcha_solution(altcha, hmac_key):
        return request.app.state.templates.TemplateResponse(
            "challenge.html",
            {"request": request, "external_path": external_path, "next": next, "error": True},
            status_code=400,
        )

    cookie_value = generate_challenge_cookie(hmac_key)
    safe_next = _safe_next(next, external_path)
    response = RedirectResponse(safe_next, status_code=303)
    response.set_cookie(
        key=CHALLENGE_COOKIE_NAME,
        value=cookie_value,
        httponly=True,
        secure=request.app.state.settings.secure_cookies,
        samesite="strict",
        path="/",
        max_age=300,
    )
    return response
