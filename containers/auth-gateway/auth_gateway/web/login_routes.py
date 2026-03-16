from auth_gateway.models.auth import OIDCMethodModel
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
    get_runtime_config,
    get_session,
    get_totp_method,
    resolve_context_from_request,
    session_is_allowed,
)
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

router = APIRouter()


def _render(request: Request, template_name: str, status_code: int = 200, **context):
    templates = request.app.state.templates
    base_context = {
        "request": request,
        "external_path": request.app.state.settings.external_path,
    }
    base_context.update(context)
    return templates.TemplateResponse(template_name, base_context, status_code=status_code)


def _redirect_with_cookie(request: Request, destination: str, session) -> RedirectResponse:
    response = RedirectResponse(destination, status_code=303)
    response.set_cookie(
        key=request.app.state.settings.cookie_name,
        value=session.session_id,
        httponly=True,
        secure=request.app.state.settings.secure_cookies,
        samesite="lax",
        path="/",
    )
    return response


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/"):
    runtime_config = get_runtime_config(request)
    session = get_session(request)
    context = resolve_context_from_request(request, runtime_config, next)
    effective_policy = get_effective_policy(runtime_config, context.policy_name)

    if effective_policy.mode == "deny":
        return _render(request, "error.html", status_code=403, title="Access denied", message="This route is blocked by policy.")
    if effective_policy.mode == "bypass":
        return RedirectResponse(next, status_code=303)

    if session and session_is_allowed(session, effective_policy):
        current_factors = set(session.auth_factors)
        if effective_policy.ip_method_names:
            client_ip = extract_client_ip(request.headers.get("x-forwarded-for", ""))
            if evaluate_ip_access(runtime_config, effective_policy, client_ip):
                current_factors.add("ip")
        missing_factors = [factor for factor in effective_policy.required_factors if factor not in current_factors]
        if not missing_factors:
            return RedirectResponse(next, status_code=303)
        if missing_factors == ["totp"]:
            return RedirectResponse(build_external_url(request, "/login/totp", next=next), status_code=303)
        if missing_factors == ["oidc"]:
            return RedirectResponse(build_external_url(request, "/login/oidc/start", next=next), status_code=303)

    available_methods = []
    if effective_policy.password_method_names:
        available_methods.append("password")
    if effective_policy.oidc_method_names:
        available_methods.append("oidc")
    if effective_policy.totp_method_names and not effective_policy.password_method_names and not effective_policy.oidc_method_names:
        available_methods.append("totp")

    if available_methods == ["password"]:
        return RedirectResponse(build_external_url(request, "/login/password", next=next), status_code=303)
    if available_methods == ["oidc"]:
        return RedirectResponse(build_external_url(request, "/login/oidc/start", next=next), status_code=303)
    if available_methods == ["totp"]:
        return RedirectResponse(build_external_url(request, "/login/totp", next=next), status_code=303)

    return _render(
        request,
        "login.html",
        next=next,
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
    return _render(request, "login_password.html", next=next, application_name=context.application.name, error=None)


@router.post("/login/password")
async def login_password_submit(request: Request, next: str = Form("/"), username: str = Form(...), password: str = Form(...)):
    runtime_config = get_runtime_config(request)
    context = resolve_context_from_request(request, runtime_config, next)
    effective_policy = get_effective_policy(runtime_config, context.policy_name)
    user = verify_user_password(username, password, runtime_config.users)

    if not user:
        return _render(request, "login_password.html", status_code=401, next=next, application_name=context.application.name, error="Invalid username or password.")
    if effective_policy.allowed_users and username not in effective_policy.allowed_users:
        return _render(request, "login_password.html", status_code=403, next=next, application_name=context.application.name, error="This user is not allowed by the active policy.")

    groups = [
        group_name
        for group_name, group in runtime_config.groups.items()
        if username in group.users
    ]
    session_service = request.app.state.session_service
    session = session_service.issue_session(
        existing_session=get_session(request),
        username=username,
        email=user.email or None,
        groups=groups,
        add_factors=["password"],
        expires_in_minutes=get_effective_expiration(request, effective_policy, ["password"]),
    )

    if effective_policy.totp_method_names:
        return _redirect_with_cookie(request, build_external_url(request, "/login/totp", next=next), session)
    return _redirect_with_cookie(request, next, session)


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
    return _render(request, "login_totp.html", next=next, application_name=context.application.name, error=None)


@router.post("/login/totp")
async def login_totp_submit(request: Request, next: str = Form("/"), token: str = Form(...)):
    runtime_config = get_runtime_config(request)
    context = resolve_context_from_request(request, runtime_config, next)
    effective_policy = get_effective_policy(runtime_config, context.policy_name)
    session = get_session(request)

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
        return _render(request, "login_totp.html", status_code=401, next=next, application_name=context.application.name, error="Invalid verification code.")

    session_service = request.app.state.session_service
    refreshed_session = session_service.issue_session(
        existing_session=session,
        add_factors=["totp"],
        expires_in_minutes=get_effective_expiration(request, effective_policy, ["totp"]),
    )
    return _redirect_with_cookie(request, next, refreshed_session)


@router.get("/login/oidc/start")
async def login_oidc_start(request: Request, next: str = "/"):
    runtime_config = get_runtime_config(request)
    context = resolve_context_from_request(request, runtime_config, next)
    effective_policy = get_effective_policy(runtime_config, context.policy_name)
    method_name, method = get_oidc_method(runtime_config, effective_policy)
    if not method_name or not method:
        return _render(request, "error.html", status_code=400, title="OIDC unavailable", message="The selected policy does not require OIDC.")

    session_state = request.app.state.session_service.create_oidc_state(method_name, normalize_host(request.headers.get("host", "")), next)
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

    context = resolve_context_from_request(request, runtime_config, oidc_state.next_url)
    effective_policy = get_effective_policy(runtime_config, context.policy_name)
    method = runtime_config.auth_methods.get(oidc_state.method_name)
    if not isinstance(method, OIDCMethodModel):
        return _render(request, "error.html", status_code=400, title="OIDC configuration missing", message="The referenced OIDC method is no longer available.")

    identity = await request.app.state.oidc_service.finish_callback(request, oidc_state.method_name, method, oidc_state.nonce)
    if not is_oidc_identity_allowed(method, identity.email):
        return _render(request, "error.html", status_code=403, title="OIDC access denied", message="The authenticated OIDC identity is not allowed by the configured allowlists.")

    session = request.app.state.session_service.issue_session(
        existing_session=get_session(request),
        email=identity.email,
        subject=identity.subject,
        metadata={"oidc_claims": identity.claims},
        add_factors=["oidc"],
        expires_in_minutes=get_effective_expiration(request, effective_policy, ["oidc"]),
    )
    if effective_policy.totp_method_names:
        return _redirect_with_cookie(request, build_external_url(request, "/login/totp", next=oidc_state.next_url), session)
    return _redirect_with_cookie(request, oidc_state.next_url, session)


@router.post("/logout")
async def logout(request: Request, next: str = Form("/")):
    session_cookie = request.cookies.get(request.app.state.settings.cookie_name)
    request.app.state.session_service.delete_session(session_cookie)
    response = RedirectResponse(next or "/", status_code=303)
    response.delete_cookie(request.app.state.settings.cookie_name, path="/")
    return response
