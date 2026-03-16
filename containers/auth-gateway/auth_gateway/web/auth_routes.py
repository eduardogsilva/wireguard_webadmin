from auth_gateway.services.policy_engine import evaluate_ip_access, extract_client_ip
from auth_gateway.services.resolver import resolve_request_context
from auth_gateway.web.dependencies import (
    build_external_url,
    get_effective_policy,
    get_runtime_config,
    get_session,
    session_is_allowed,
)
from fastapi import APIRouter, Request, Response
from fastapi.responses import PlainTextResponse, RedirectResponse

router = APIRouter()


@router.get("/auth/check")
async def auth_check(request: Request):
    runtime_config = get_runtime_config(request)
    forwarded_host = request.headers.get("x-forwarded-host", request.headers.get("host", ""))
    forwarded_uri = request.headers.get("x-forwarded-uri", "/")
    context = resolve_request_context(runtime_config, forwarded_host, forwarded_uri)
    if not context:
        return PlainTextResponse("Application was not found.", status_code=403)

    effective_policy = get_effective_policy(runtime_config, context.policy_name)
    if effective_policy.mode == "error":
        return PlainTextResponse(effective_policy.error_message or "Policy configuration error.", status_code=500)
    if effective_policy.mode == "deny":
        return PlainTextResponse("Access denied by policy.", status_code=403)
    if effective_policy.mode == "bypass":
        return PlainTextResponse("OK", status_code=200)

    client_ip = extract_client_ip(request.headers.get("x-forwarded-for", ""))
    ip_allowed = evaluate_ip_access(runtime_config, effective_policy, client_ip)
    if effective_policy.ip_method_names and not ip_allowed:
        return PlainTextResponse("Access denied for this IP address.", status_code=403)

    session = get_session(request)
    if not session_is_allowed(session, effective_policy):
        if session and session.username:
            return PlainTextResponse("Authenticated user is not allowed by this policy.", status_code=403)
        login_url = build_external_url(request, "/login", next=context.path)
        return RedirectResponse(login_url, status_code=302)

    current_factors = set(session.auth_factors if session else [])
    if ip_allowed:
        current_factors.add("ip")

    missing_factors = [factor for factor in effective_policy.required_factors if factor not in current_factors]
    if missing_factors:
        login_url = build_external_url(request, "/login", next=context.path)
        return RedirectResponse(login_url, status_code=302)

    response = PlainTextResponse("OK", status_code=200)
    if session:
        if session.username:
            response.headers["X-Auth-User"] = session.username
        if session.email:
            response.headers["X-Auth-Email"] = session.email
        if session.groups:
            response.headers["X-Auth-Groups"] = ",".join(session.groups)
        if session.auth_factors:
            response.headers["X-Auth-Factors"] = ",".join(session.auth_factors)
    response.headers["X-Auth-Policy"] = effective_policy.name
    return response
