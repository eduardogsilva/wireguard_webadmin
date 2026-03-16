import logging

from auth_gateway.models.auth import OIDCMethodModel

logger = logging.getLogger("uvicorn.error")
from auth_gateway.services.oidc_service import is_oidc_identity_allowed
from auth_gateway.services.password_service import verify_user_password
from auth_gateway.services.policy_engine import evaluate_ip_access, extract_client_ip
from auth_gateway.services.resolver import normalize_host
from auth_gateway.services.totp_service import verify_totp
from auth_gateway.web.dependencies import (
    build_external_url,
    get_effective_expiration,
    get_effective_policy,
    get_oidc_method,
    get_or_create_csrf_token,
    get_runtime_config,
    get_session,
    get_totp_method,
    resolve_context_from_request,
    set_csrf_cookie,
    session_is_allowed,
    validate_csrf,
)
from auth_gateway.limiter import AUTH_RATE_LIMIT, limiter
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

router = APIRouter()


def _render(request: Request, template_name: str, status_code: int = 200, **context):
    templates = request.app.state.templates
    base_context = {
        "request": request,
        "external_path": request.app.state.settings.external_path,
    }
    base_context.update(context)
    response = templates.TemplateResponse(template_name, base_context, status_code=status_code)
    csrf_token = context.get("csrf_token")
    if csrf_token:
        set_csrf_cookie(request, response, csrf_token)
    return response


def _redirect_with_cookie(request: Request, destination: str, session) -> RedirectResponse:
    response = RedirectResponse(destination, status_code=303)
    response.set_cookie(
        key=request.app.state.settings.cookie_name,
        value=session.session_id,
        httponly=True,
        secure=request.app.state.settings.secure_cookies,
        samesite="strict",
        path="/",
    )
    return response


def _create_authenticated_session(request: Request, *, username=None, email=None, subject=None, groups=None, metadata=None, factors=None, expires_in_minutes=None):
    existing_session = get_session(request)
    if existing_session:
        request.app.state.session_service.delete_session(existing_session.session_id)
    return request.app.state.session_service.issue_session(
        username=username,
        email=email,
        subject=subject,
        groups=groups,
        metadata=metadata,
        add_factors=factors,
        expires_in_minutes=expires_in_minutes,
    )


def _csrf_error(request: Request, next_path: str, application_name: str | None = None):
    return _render(
        request,
        "error.html",
        status_code=403,
        title="Invalid form submission",
        message="The form security token is missing or invalid. Please try again.",
        next=next_path,
        application_name=application_name,
        csrf_token=get_or_create_csrf_token(request),
    )


@router.get("/", response_class=HTMLResponse)
async def session_page(request: Request):
    session = get_session(request)
    if not session or not session.auth_factors:
        return RedirectResponse(build_external_url(request, "/login"), status_code=303)
    return _render(request, "session.html", session=session, csrf_token=get_or_create_csrf_token(request))


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/"):
    runtime_config = get_runtime_config(request)
    session = get_session(request)
    context = resolve_context_from_request(request, runtime_config, next)
    effective_policy = get_effective_policy(runtime_config, context.policy_name)

    if effective_policy.mode == "error":
        return _render(request, "error.html", status_code=500, title="Configuration error", message=effective_policy.error_message or "A policy configuration error has been detected.")
    if effective_policy.mode == "deny":
        return _render(request, "error.html", status_code=403, title="Access denied", message="This route is blocked by policy.")
    if effective_policy.mode == "bypass":
        return RedirectResponse(context.path, status_code=303)

    if session and session_is_allowed(session, effective_policy):
        current_factors = set(session.auth_factors)
        if effective_policy.ip_method_names:
            client_ip = extract_client_ip(request.headers.get("x-forwarded-for", ""))
            if evaluate_ip_access(runtime_config, effective_policy, client_ip):
                current_factors.add("ip")
        missing_factors = [factor for factor in effective_policy.required_factors if factor not in current_factors]
        if not missing_factors:
            return RedirectResponse(context.path, status_code=303)
        if missing_factors == ["totp"]:
            return RedirectResponse(build_external_url(request, "/login/totp", next=context.path), status_code=303)
        if missing_factors == ["oidc"]:
            return RedirectResponse(build_external_url(request, "/login/oidc/start", next=context.path), status_code=303)

    available_methods = []
    if effective_policy.password_method_names:
        available_methods.append("password")
    if effective_policy.oidc_method_names:
        available_methods.append("oidc")
    if effective_policy.totp_method_names and not effective_policy.password_method_names and not effective_policy.oidc_method_names:
        available_methods.append("totp")

    if available_methods == ["password"]:
        return RedirectResponse(build_external_url(request, "/login/password", next=context.path), status_code=303)
    if available_methods == ["oidc"]:
        return RedirectResponse(build_external_url(request, "/login/oidc/start", next=context.path), status_code=303)
    if available_methods == ["totp"]:
        return RedirectResponse(build_external_url(request, "/login/totp", next=context.path), status_code=303)

    return _render(
        request,
        "login.html",
        next=context.path,
        methods=available_methods,
        application_name=context.application.name,
        policy_name=context.policy_name,
    )


@router.get("/login/password", response_class=HTMLResponse)
async def login_password_page(request: Request, next: str = "/"):
    runtime_config = get_runtime_config(request)
    context = resolve_context_from_request(request, runtime_config, next)
    effective_policy = get_effective_policy(runtime_config, context.policy_name)
    if not effective_policy.password_method_names:
        return _render(request, "error.html", status_code=400, title="Password login unavailable", message="The selected policy does not require a password step.")
    return _render(
        request,
        "login_password.html",
        next=next,
        application_name=context.application.name,
        error=None,
        csrf_token=get_or_create_csrf_token(request),
    )


@router.post("/login/password")
@limiter.limit(AUTH_RATE_LIMIT)
async def login_password_submit(
    request: Request,
    next: str = Form("/"),
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
):
    runtime_config = get_runtime_config(request)
    context = resolve_context_from_request(request, runtime_config, next)
    effective_policy = get_effective_policy(runtime_config, context.policy_name)
    try:
        validate_csrf(request, csrf_token)
    except HTTPException:
        return _csrf_error(request, next, context.application.name)
    user = verify_user_password(username, password, runtime_config.users)

    if not user:
        logger.warning("AUTH password failed for '%s' (policy: %s)", username, context.policy_name)
        return _render(
            request,
            "login_password.html",
            status_code=401,
            next=next,
            application_name=context.application.name,
            error="Invalid username or password.",
            csrf_token=get_or_create_csrf_token(request),
        )
    if effective_policy.allowed_users and username not in effective_policy.allowed_users:
        logger.warning("AUTH password denied for '%s' — not in allowed_users (policy: %s)", username, context.policy_name)
        return _render(
            request,
            "login_password.html",
            status_code=403,
            next=next,
            application_name=context.application.name,
            error="This user is not allowed by the active policy.",
            csrf_token=get_or_create_csrf_token(request),
        )

    groups = [
        group_name
        for group_name, group in runtime_config.groups.items()
        if username in group.users
    ]
    session = _create_authenticated_session(
        request,
        username=username,
        email=user.email or None,
        groups=groups,
        factors=["password"],
        expires_in_minutes=get_effective_expiration(request, effective_policy, ["password"]),
    )

    if effective_policy.totp_method_names:
        logger.info("AUTH password ok for '%s' → totp required (policy: %s)", username, context.policy_name)
        return _redirect_with_cookie(request, build_external_url(request, "/login/totp", next=context.path), session)
    logger.info("AUTH login ok for '%s' (policy: %s)", username, context.policy_name)
    return _redirect_with_cookie(request, context.path, session)


@router.get("/login/totp", response_class=HTMLResponse)
async def login_totp_page(request: Request, next: str = "/"):
    runtime_config = get_runtime_config(request)
    context = resolve_context_from_request(request, runtime_config, next)
    effective_policy = get_effective_policy(runtime_config, context.policy_name)
    if not effective_policy.totp_method_names:
        return _render(request, "error.html", status_code=400, title="TOTP unavailable", message="The selected policy does not require a TOTP step.")
    if effective_policy.password_method_names:
        session = get_session(request)
        if not session or "password" not in session.auth_factors:
            return RedirectResponse(build_external_url(request, "/login/password", next=next), status_code=303)
    return _render(
        request,
        "login_totp.html",
        next=next,
        application_name=context.application.name,
        error=None,
        csrf_token=get_or_create_csrf_token(request),
    )


@router.post("/login/totp")
@limiter.limit(AUTH_RATE_LIMIT)
async def login_totp_submit(request: Request, next: str = Form("/"), token: str = Form(...), csrf_token: str = Form(...)):
    runtime_config = get_runtime_config(request)
    context = resolve_context_from_request(request, runtime_config, next)
    effective_policy = get_effective_policy(runtime_config, context.policy_name)
    session = get_session(request)
    try:
        validate_csrf(request, csrf_token)
    except HTTPException:
        return _csrf_error(request, next, context.application.name)

    if effective_policy.password_method_names and (not session or "password" not in session.auth_factors):
        return RedirectResponse(build_external_url(request, "/login/password", next=next), status_code=303)
    if effective_policy.oidc_method_names and (not session or "oidc" not in session.auth_factors):
        return RedirectResponse(build_external_url(request, "/login/oidc/start", next=next), status_code=303)

    method_name, method = get_totp_method(runtime_config, effective_policy)
    if not method_name or not method:
        return _render(request, "error.html", status_code=400, title="TOTP configuration missing", message="No usable TOTP method is configured for this policy.")

    secret = method.totp_secret or ""
    if session and session.username:
        user = runtime_config.users.get(session.username)
        if user and user.totp_secret:
            secret = user.totp_secret

    if not verify_totp(secret, token):
        logger.warning("AUTH totp failed for '%s' (policy: %s)", session.username if session else "?", context.policy_name)
        return _render(
            request,
            "login_totp.html",
            status_code=401,
            next=next,
            application_name=context.application.name,
            error="Invalid verification code.",
            csrf_token=get_or_create_csrf_token(request),
        )

    session_service = request.app.state.session_service
    refreshed_session = session_service.issue_session(
        existing_session=session,
        add_factors=["totp"],
        expires_in_minutes=get_effective_expiration(request, effective_policy, ["totp"]),
    )
    logger.info("AUTH login ok for '%s' via password+totp (policy: %s)", refreshed_session.username, context.policy_name)
    return _redirect_with_cookie(request, context.path, refreshed_session)


@router.get("/login/oidc/start")
@limiter.limit(AUTH_RATE_LIMIT)
async def login_oidc_start(request: Request, next: str = "/"):
    runtime_config = get_runtime_config(request)
    context = resolve_context_from_request(request, runtime_config, next)
    effective_policy = get_effective_policy(runtime_config, context.policy_name)
    method_name, method = get_oidc_method(runtime_config, effective_policy)
    if not method_name or not method:
        return _render(request, "error.html", status_code=400, title="OIDC unavailable", message="The selected policy does not require OIDC.")

    session_state = request.app.state.session_service.create_oidc_state(method_name, normalize_host(request.headers.get("host", "")), context.path)
    redirect_uri = build_external_url(request, "/login/oidc/callback")
    return await request.app.state.oidc_service.build_authorization_redirect(
        request,
        method_name,
        method,
        redirect_uri,
        session_state.state,
        session_state.nonce,
    )


@router.get("/login/oidc/callback")
async def login_oidc_callback(request: Request, state: str):
    runtime_config = get_runtime_config(request)
    oidc_state = request.app.state.session_service.consume_oidc_state(state)
    if not oidc_state:
        return _render(request, "error.html", status_code=400, title="Invalid OIDC state", message="The OIDC login state is missing or expired.")

    callback_host = normalize_host(request.headers.get("host", ""))
    if oidc_state.host != callback_host:
        logger.warning("OIDC callback host mismatch: expected '%s', got '%s'", oidc_state.host, callback_host)
        return _render(request, "error.html", status_code=400, title="OIDC callback host mismatch", message="The OIDC callback host does not match the original request host.")

    context = resolve_context_from_request(request, runtime_config, oidc_state.next_url)
    effective_policy = get_effective_policy(runtime_config, context.policy_name)
    method = runtime_config.auth_methods.get(oidc_state.method_name)
    if not isinstance(method, OIDCMethodModel):
        return _render(request, "error.html", status_code=400, title="OIDC configuration missing", message="The referenced OIDC method is no longer available.")

    identity = await request.app.state.oidc_service.finish_callback(request, oidc_state.method_name, method, oidc_state.nonce)
    if not is_oidc_identity_allowed(method, identity.email):
        return _render(request, "error.html", status_code=403, title="OIDC access denied", message="The authenticated OIDC identity is not allowed by the configured allowlists.")

    session = _create_authenticated_session(
        request,
        email=identity.email,
        subject=identity.subject,
        metadata={"oidc_claims": identity.claims},
        factors=["oidc"],
        expires_in_minutes=get_effective_expiration(request, effective_policy, ["oidc"]),
    )
    if effective_policy.totp_method_names:
        return _redirect_with_cookie(request, build_external_url(request, "/login/totp", next=oidc_state.next_url), session)
    return _redirect_with_cookie(request, oidc_state.next_url, session)


def _safe_redirect_path(url: str | None) -> str:
    """Accept only relative paths to prevent open redirects."""
    if not url or "://" in url or not url.startswith("/"):
        return "/"
    return url


def _do_logout(request: Request, next_url: str = "/") -> RedirectResponse:
    session_cookie = request.cookies.get(request.app.state.settings.cookie_name)
    session = request.app.state.session_service.get_session(session_cookie)
    request.app.state.session_service.delete_session(session_cookie)
    if session:
        logger.info("AUTH logout for '%s'", session.username or session.email or "unknown")
    response = RedirectResponse(_safe_redirect_path(next_url), status_code=303)
    response.delete_cookie(request.app.state.settings.cookie_name, path="/")
    return response


@router.get("/logout")
async def logout_get(request: Request, next: str = "/"):
    return _do_logout(request, next)


@router.post("/logout")
async def logout_post(request: Request, next: str = Form("/"), csrf_token: str = Form(...)):
    try:
        validate_csrf(request, csrf_token)
    except HTTPException:
        return _csrf_error(request, next)
    return _do_logout(request, next)
