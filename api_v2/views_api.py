import ipaddress
import json
from functools import wraps
from typing import List, Optional, Tuple

from django.db import transaction
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from api.views import func_get_wireguard_status
from routing_templates.models import RoutingTemplate
from wireguard.models import Peer, PeerAllowedIP, WireGuardInstance
from wireguard_peer.functions import func_create_new_peer
from wireguard_tools.functions import func_reload_wireguard_interface
from wireguard_tools.views import export_wireguard_configuration
from .models import ApiKey


def api_doc(*, summary: str, auth: str, params: list, returns: list, methods: Optional[List[str]] = None, examples: Optional[dict] = None):
    def decorator(view_func):
        view_func.api_doc = {
            "summary": summary,
            "auth": auth,
            "params": params,
            "returns": returns,
            "methods": methods or ["POST"],
            "examples": examples or {},
        }

        @wraps(view_func)
        def wrapper(*args, **kwargs):
            return view_func(*args, **kwargs)

        return wrapper
    return decorator


def validate_api_key(request, wireguard_instance: WireGuardInstance | None = None):
    """
    Validates the API token and optionally validates access to a given WireGuard instance.

    Rules:
      - token must exist and be enabled
      - if ApiKey.allowed_instances is empty => key can access any instance
      - otherwise, wireguard_instance must be included in ApiKey.allowed_instances

    Notes:
      - If wireguard_instance is None, only validates the token (no instance scoping).
    """
    token = request.headers.get("token")
    if not token:
        return None, "Missing API token."

    try:
        api_key = ApiKey.objects.get(token=token, enabled=True)
    except ApiKey.DoesNotExist:
        return None, "Invalid API key."

    if wireguard_instance is not None:
        if api_key.allowed_instances.exists():
            if not api_key.allowed_instances.filter(uuid=wireguard_instance.uuid).exists():
                return None, "This API key is not allowed to access the requested instance."

    return api_key, ""

def _parse_ipv4_cidrs(value) -> Tuple[Optional[List[Tuple[str, int]]], Optional[str]]:
    """
    Parses a list of CIDR strings into [(allowed_ip, netmask), ...].

    Example:
      ["10.0.0.0/24"] => [("10.0.0.0", 24)]
    """
    if value is None:
        return None, None

    if not isinstance(value, list):
        return None, "Invalid payload: networks must be a list of CIDR strings."

    pairs: List[Tuple[str, int]] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            return None, "Invalid payload: each network must be a non-empty string."

        try:
            network = ipaddress.ip_network(item.strip(), strict=False)
        except Exception:
            return None, f"Invalid network: {item}"

        if network.version != 4:
            return None, f"Only IPv4 networks are supported: {item}"

        pairs.append((str(network.network_address), int(network.prefixlen)))

    # De-duplicate while preserving order
    seen = set()
    unique: List[Tuple[str, int]] = []
    for pair in pairs:
        if pair not in seen:
            seen.add(pair)
            unique.append(pair)

    return unique, None


def _sync_allowed_ips(peer: Peer, desired_pairs: Optional[List[Tuple[str, int]]], *, config_file: str) -> None:
    """
    Sync PeerAllowedIP rows for a peer/config_file, only for priority >= 1.

    - Adds missing (allowed_ip, netmask)
    - Removes extra (allowed_ip, netmask)
    - Never touches priority=0 entries (peer main address)
    """
    if desired_pairs is None:
        return

    current_qs = PeerAllowedIP.objects.filter(peer=peer, config_file=config_file, priority__gte=1)
    current_pairs = set(current_qs.values_list("allowed_ip", "netmask"))
    desired_set = set(desired_pairs)

    pairs_to_remove = current_pairs - desired_set
    pairs_to_add = desired_set - current_pairs

    for allowed_ip, netmask in pairs_to_remove:
        PeerAllowedIP.objects.filter(
            peer=peer,
            config_file=config_file,
            priority__gte=1,
            allowed_ip=allowed_ip,
            netmask=netmask,
        ).delete()

    for allowed_ip, netmask in pairs_to_add:
        PeerAllowedIP.objects.create(
            peer=peer,
            config_file=config_file,
            priority=1,
            allowed_ip=allowed_ip,
            netmask=int(netmask),
        )


def _apply_reload_or_pending_changes(*, wireguard_instance: WireGuardInstance, skip_reload: bool) -> Tuple[bool, str]:
    """
    Applies changes after create/update/delete.

    If skip_reload=True:
      - sets pending_changes=True

    Else:
      - exports WireGuard configuration
      - reloads the interface
    """
    if skip_reload:
        wireguard_instance.pending_changes = True
        wireguard_instance.save(update_fields=["pending_changes", "updated"])
        return True, "Changes saved. Reload skipped (pending_changes set to True)."

    export_wireguard_configuration(wireguard_instance)
    success, message = func_reload_wireguard_interface(wireguard_instance)
    return bool(success), str(message or "")


def _get_wireguard_instance(instance_name: str) -> Optional[WireGuardInstance]:

    return

@csrf_exempt
@api_doc(
    summary="Create / Update / Delete a WireGuard peer (and optionally reload the interface)",
    auth="Header token: <ApiKey.token>",
    methods=["POST", "PUT", "DELETE"],
    params=[
        {"name": "instance", "in": "json", "type": "string", "required": True, "example": "wg0",
         "description": "Target instance name in the format wg{instance_id} (e.g. wg0, wg1)."},
        {"name": "skip_reload", "in": "json", "type": "boolean", "required": False, "example": True,
         "description": "If true, does not reload the interface and only sets wireguard_instance.pending_changes=True."},

        {"name": "peer_uuid", "in": "json", "type": "string", "required": False,
         "description": "Peer UUID used to select the peer for update/delete."},
        {"name": "peer_public_key", "in": "json", "type": "string", "required": False,
         "description": "Peer public key used to select the peer for update/delete."},

        {"name": "routing_template_uuid", "in": "json", "type": "string", "required": False,
         "description": "Routing template UUID (optional). Must belong to the same WireGuard instance."},

        {"name": "announced_networks", "in": "json", "type": "list[string]", "required": False,
         "example": ["10.10.0.0/24"], "description": "Server announced networks (priority>=1). Will be synced."},
        {"name": "client_routes", "in": "json", "type": "list[string]", "required": False,
         "example": ["192.168.1.0/24"],
         "description": "Client routes (priority>=1). Will be synced. Not allowed when allow_peer_custom_routes=True."},

        {"name": "public_key", "in": "json", "type": "string", "required": False,
         "description": "Peer public key (create/update)."},
        {"name": "pre_shared_key", "in": "json", "type": "string", "required": False,
         "description": "Peer pre-shared key (create/update)."},
        {"name": "private_key", "in": "json", "type": "string", "required": False,
         "description": "Peer private key (create/update). Optional."},
        {"name": "persistent_keepalive", "in": "json", "type": "integer", "required": False,
         "description": "Persistent keepalive (create/update)."},
        {"name": "suspended", "in": "json", "type": "boolean", "required": False,
         "description": "Suspend/unsuspend a peer (update)."},
        {"name": "suspend_reason", "in": "json", "type": "string", "required": False,
         "description": "Suspend reason (update). Can be cleared by sending null/empty string."},
    ],
    returns=[
        {"status": 200, "body": {"status": "success", "message": "Peer updated successfully.", "peer_uuid": "...", "public_key": "...", "reload": {"success": True, "message": "..."}}},
        {"status": 201, "body": {"status": "success", "message": "Peer created successfully.", "peer_uuid": "...", "public_key": "...", "reload": {"success": True, "message": "..."}}},
        {"status": 400, "body": {"status": "error", "error_message": "Invalid payload: ..."}},
        {"status": 403, "body": {"status": "error", "error_message": "Invalid API key."}},
        {"status": 405, "body": {"status": "error", "error_message": "Method not allowed."}},
    ],
    examples={
        "create_skip_reload": {
            "method": "POST",
            "json": {
                "instance": "wg0",
                "name": "John",
                "routing_template_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "announced_networks": ["10.10.0.0/24"],
                "skip_reload": True
            }
        },
        "update_with_reload": {
            "method": "PUT",
            "json": {
                "instance": "wg0",
                "peer_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "suspended": True,
                "suspend_reason": "Maintenance window",
                "skip_reload": False
            }
        }
    }
)
def api_v2_manage_peer(request):
    if request.method not in ("POST", "PUT", "DELETE"):
        return JsonResponse({"status": "error", "error_message": "Method not allowed."}, status=405)

    try:
        payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    except Exception:
        return JsonResponse({"status": "error", "error_message": "Invalid JSON body."}, status=400)

    try:
        wireguard_instance = WireGuardInstance.objects.get(instance_id=int(payload.get("instance",).replace("wg", "")))
    except:
        wireguard_instance = None

    if not wireguard_instance:
        return JsonResponse({"status": "error", "error_message": "Invalid or missing WireGuard instance."}, status=400)

    api_key, api_error = validate_api_key(request, wireguard_instance)
    if not api_key:
        return JsonResponse({"status": "error", "error_message": api_error}, status=403)

    skip_reload = bool(payload.get("skip_reload", False))

    # Routing template (optional) - must belong to the same instance
    routing_template_uuid = payload.get("routing_template_uuid")
    routing_template = None
    if routing_template_uuid:
        routing_template = RoutingTemplate.objects.filter(uuid=routing_template_uuid).first()
        if not routing_template:
            return JsonResponse({"status": "error", "error_message": "Invalid routing_template_uuid."}, status=400)
        if routing_template.wireguard_instance_id != wireguard_instance.uuid:
            return JsonResponse(
                {"status": "error", "error_message": "routing_template_uuid does not belong to the requested instance."},
                status=400
            )

    # Parse networks (only if provided)
    announced_pairs, announced_error = _parse_ipv4_cidrs(payload.get("announced_networks"))
    if announced_error:
        return JsonResponse({"status": "error", "error_message": announced_error}, status=400)

    client_route_pairs, client_route_error = _parse_ipv4_cidrs(payload.get("client_routes"))
    if client_route_error:
        return JsonResponse({"status": "error", "error_message": client_route_error}, status=400)

    with transaction.atomic():
        # CREATE
        if request.method == "POST":
            peer_name = payload.get("name", "") or ""
            peer_public_key = payload.get("public_key") or None
            peer_pre_shared_key = payload.get("pre_shared_key") or None
            peer_private_key = payload.get("private_key") or None  # optional

            peer_persistent_keepalive = payload.get("persistent_keepalive")
            if peer_persistent_keepalive is not None:
                try:
                    peer_persistent_keepalive = int(peer_persistent_keepalive)
                except Exception:
                    return JsonResponse({"status": "error", "error_message": "Invalid persistent_keepalive."}, status=400)

            peer_allowed_ip = payload.get("allowed_ip") or None
            peer_allowed_ip_netmask = payload.get("allowed_ip_netmask")
            if peer_allowed_ip_netmask is not None:
                try:
                    peer_allowed_ip_netmask = int(peer_allowed_ip_netmask)
                except Exception:
                    return JsonResponse({"status": "error", "error_message": "Invalid allowed_ip_netmask."}, status=400)

            create_overrides = {"name": peer_name}

            if peer_public_key:
                create_overrides["public_key"] = peer_public_key
            if peer_pre_shared_key:
                create_overrides["pre_shared_key"] = peer_pre_shared_key
            if peer_private_key:
                create_overrides["private_key"] = peer_private_key
            if peer_persistent_keepalive is not None:
                create_overrides["persistent_keepalive"] = peer_persistent_keepalive
            if peer_allowed_ip:
                create_overrides["allowed_ip"] = str(peer_allowed_ip).strip()
            if peer_allowed_ip_netmask is not None:
                create_overrides["allowed_ip_netmask"] = peer_allowed_ip_netmask

            if routing_template is not None:
                create_overrides["default_routing_template"] = routing_template

            created_peer, create_message = func_create_new_peer(wireguard_instance=wireguard_instance, overrides=create_overrides)
            if not created_peer:
                return JsonResponse({"status": "error", "error_message": create_message or "Error creating peer."}, status=400)

            # Enforce allow_peer_custom_routes rule:
            # If template allows peer custom routes, client_routes must NOT be provided.
            if routing_template is not None and routing_template.allow_peer_custom_routes:
                if client_route_pairs is not None and len(client_route_pairs) > 0:
                    return JsonResponse(
                        {"status": "error", "error_message": "client_routes is not allowed when routing_template.allow_peer_custom_routes is enabled."},
                        status=400
                    )

            _sync_allowed_ips(created_peer, announced_pairs, config_file="server")
            _sync_allowed_ips(created_peer, client_route_pairs, config_file="client")

            reload_success, reload_message = _apply_reload_or_pending_changes(
                wireguard_instance=created_peer.wireguard_instance,
                skip_reload=skip_reload
            )

            return JsonResponse(
                {
                    "status": "success",
                    "message": create_message or "Peer created successfully.",
                    "peer_uuid": str(created_peer.uuid),
                    "public_key": created_peer.public_key,
                    "reload": {"success": reload_success, "message": reload_message},
                },
                status=201
            )

        # UPDATE / DELETE: locate peer by uuid or public_key (explicit variable names)
        selector_peer_uuid = payload.get("peer_uuid")
        selector_peer_public_key = payload.get("peer_public_key")

        peer_for_action = None
        if selector_peer_uuid:
            peer_for_action = Peer.objects.filter(uuid=selector_peer_uuid, wireguard_instance=wireguard_instance).first()
            if not peer_for_action:
                return JsonResponse({"status": "error", "error_message": "Peer not found for the provided peer_uuid in this instance."}, status=400)
        elif selector_peer_public_key:
            peer_for_action = Peer.objects.filter(public_key=selector_peer_public_key, wireguard_instance=wireguard_instance).first()
            if not peer_for_action:
                return JsonResponse({"status": "error", "error_message": "Peer not found for the provided peer_public_key in this instance."}, status=400)
        else:
            return JsonResponse({"status": "error", "error_message": "Missing peer selector (peer_uuid or peer_public_key)."}, status=400)

        # Determine effective routing template for allow_peer_custom_routes validation
        effective_routing_template = routing_template if routing_template is not None else peer_for_action.routing_template
        if effective_routing_template is not None and effective_routing_template.allow_peer_custom_routes:
            if client_route_pairs is not None and len(client_route_pairs) > 0:
                return JsonResponse(
                    {"status": "error", "error_message": "client_routes is not allowed when routing_template.allow_peer_custom_routes is enabled."},
                    status=400
                )

        # UPDATE
        if request.method == "PUT":
            new_public_key = payload.get("public_key")
            new_pre_shared_key = payload.get("pre_shared_key")
            new_private_key = payload.get("private_key")  # optional
            new_persistent_keepalive = payload.get("persistent_keepalive")
            new_suspended = payload.get("suspended")
            new_suspend_reason = payload.get("suspend_reason") if "suspend_reason" in payload else None

            if new_public_key:
                peer_for_action.public_key = new_public_key

            if new_pre_shared_key:
                peer_for_action.pre_shared_key = new_pre_shared_key

            if new_private_key:
                peer_for_action.private_key = new_private_key

            if new_persistent_keepalive is not None:
                try:
                    peer_for_action.persistent_keepalive = int(new_persistent_keepalive)
                except Exception:
                    return JsonResponse({"status": "error", "error_message": "Invalid persistent_keepalive."}, status=400)

            if routing_template is not None:
                peer_for_action.routing_template = routing_template

            if new_suspended is not None:
                peer_for_action.suspended = bool(new_suspended)

            if "suspend_reason" in payload:
                peer_for_action.suspend_reason = new_suspend_reason

            peer_for_action.save()

            _sync_allowed_ips(peer_for_action, announced_pairs, config_file="server")
            _sync_allowed_ips(peer_for_action, client_route_pairs, config_file="client")

            reload_success, reload_message = _apply_reload_or_pending_changes(
                wireguard_instance=peer_for_action.wireguard_instance,
                skip_reload=skip_reload
            )

            return JsonResponse(
                {
                    "status": "success",
                    "message": "Peer updated successfully.",
                    "peer_uuid": str(peer_for_action.uuid),
                    "public_key": peer_for_action.public_key,
                    "reload": {"success": reload_success, "message": reload_message},
                },
                status=200
            )

        # DELETE
        deleted_uuid = str(peer_for_action.uuid)
        peer_for_action.delete()

        reload_success, reload_message = _apply_reload_or_pending_changes(
            wireguard_instance=wireguard_instance,
            skip_reload=skip_reload
        )

        return JsonResponse(
            {
                "status": "success",
                "message": "Peer deleted successfully.",
                "peer_uuid": deleted_uuid,
                "reload": {"success": reload_success, "message": reload_message},
            },
            status=200
        )


@csrf_exempt
@api_doc(
    summary="List peers for a specific instance (required)",
    auth="Header token: <ApiKey.token>",
    methods=["POST", "GET"],
    params=[
        {"name": "instance", "in": "json", "type": "string", "required": True, "example": "wg2",
         "description": "Required. Target instance name in the format wg{instance_id} (e.g. wg0, wg1)."},
    ],
    returns=[
        {"status": 200, "body": {"status": "success", "instance": "wg2", "peers": [{"uuid": "...", "public_key": "..."}]}},
        {"status": 400, "body": {"status": "error", "error_message": "Invalid or missing WireGuard instance."}},
        {"status": 403, "body": {"status": "error", "error_message": "Invalid API key."}},
    ],
    examples={
        "list_wg2": {"method": "POST", "json": {"instance": "wg2"}},
    }
)
def api_v2_peer_list(request):
    if request.method not in ("POST", "GET"):
        return JsonResponse({"status": "error", "error_message": "Method not allowed."}, status=405)

    payload = {}
    if request.method == "POST":
        try:
            payload = json.loads(request.body.decode("utf-8")) if request.body else {}
        except Exception:
            return JsonResponse({"status": "error", "error_message": "Invalid JSON body."}, status=400)
    else:
        payload = request.GET.dict()

    try:
        wireguard_instance = WireGuardInstance.objects.get(
            instance_id=int(str(payload.get("instance")).replace("wg", ""))
        )
    except Exception:
        wireguard_instance = None

    if not wireguard_instance:
        return JsonResponse({"status": "error", "error_message": "Invalid or missing WireGuard instance."}, status=400)

    api_key, api_error = validate_api_key(request, wireguard_instance=wireguard_instance)
    if not api_key:
        return JsonResponse({"status": "error", "error_message": api_error}, status=403)

    peer_qs = (
        Peer.objects
        .filter(wireguard_instance=wireguard_instance)
        .prefetch_related("peerallowedip_set")
        .order_by("sort_order", "name", "public_key")
    )

    peers = []
    for current_peer in peer_qs:
        peers.append({
            "uuid": str(current_peer.uuid),
            "name": current_peer.name or "",
            "public_key": current_peer.public_key,
            "suspended": bool(current_peer.suspended),
            "suspend_reason": current_peer.suspend_reason or "",
            "disabled_by_schedule": bool(current_peer.disabled_by_schedule),
            "main_addresses": current_peer.main_addresses,
        })

    return JsonResponse(
        {
            "status": "success",
            "instance": f"wg{wireguard_instance.instance_id}",
            "peers": peers,
        },
        status=200
    )


@csrf_exempt
@api_doc(
    summary="Peer details for a specific instance (required) by peer_uuid or peer_public_key",
    auth="Header token: <ApiKey.token>",
    methods=["POST", "GET"],
    params=[
        {"name": "instance", "in": "json", "type": "string", "required": True, "example": "wg2",
         "description": "Required. Target instance name in the format wg{instance_id} (e.g. wg0, wg1)."},
        {"name": "peer_uuid", "in": "json", "type": "string", "required": False,
         "description": "Peer UUID selector."},
        {"name": "peer_public_key", "in": "json", "type": "string", "required": False,
         "description": "Peer public key selector."},
    ],
    returns=[
        {"status": 200, "body": {"status": "success", "peer": {"uuid": "...", "name": "...", "public_key": "..."}}},
        {"status": 400, "body": {"status": "error", "error_message": "Missing peer selector (peer_uuid or peer_public_key)."}},
        {"status": 404, "body": {"status": "error", "error_message": "Peer not found."}},
        {"status": 403, "body": {"status": "error", "error_message": "Invalid API key."}},
    ],
    examples={
        "detail_by_uuid": {"method": "POST", "json": {"instance": "wg2", "peer_uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}},
        "detail_by_public_key": {"method": "POST", "json": {"instance": "wg2", "peer_public_key": "BASE64PUBLICKEY..."}},
    }
)
def api_v2_peer_detail(request):
    if request.method not in ("POST", "GET"):
        return JsonResponse({"status": "error", "error_message": "Method not allowed."}, status=405)

    payload = {}
    if request.method == "POST":
        try:
            payload = json.loads(request.body.decode("utf-8")) if request.body else {}
        except Exception:
            return JsonResponse({"status": "error", "error_message": "Invalid JSON body."}, status=400)
    else:
        payload = request.GET.dict()

    try:
        wireguard_instance = WireGuardInstance.objects.get(
            instance_id=int(str(payload.get("instance")).replace("wg", ""))
        )
    except Exception:
        wireguard_instance = None

    if not wireguard_instance:
        return JsonResponse({"status": "error", "error_message": "Invalid or missing WireGuard instance."}, status=400)

    api_key, api_error = validate_api_key(request, wireguard_instance=wireguard_instance)
    if not api_key:
        return JsonResponse({"status": "error", "error_message": api_error}, status=403)

    selector_peer_uuid = payload.get("peer_uuid")
    selector_peer_public_key = payload.get("peer_public_key")

    if not selector_peer_uuid and not selector_peer_public_key:
        return JsonResponse(
            {"status": "error", "error_message": "Missing peer selector (peer_uuid or peer_public_key)."},
            status=400,
        )

    peer_qs = (
        Peer.objects
        .filter(wireguard_instance=wireguard_instance)
        .select_related("routing_template", "wireguard_instance")
        .prefetch_related("peerallowedip_set")
    )

    if selector_peer_uuid:
        current_peer = peer_qs.filter(uuid=selector_peer_uuid).first()
    else:
        current_peer = peer_qs.filter(public_key=selector_peer_public_key).first()

    if not current_peer:
        return JsonResponse({"status": "error", "error_message": "Peer not found."}, status=404)

    peer_data = {
        "uuid": str(current_peer.uuid),
        "name": current_peer.name or "",
        "public_key": current_peer.public_key,
        "pre_shared_key": current_peer.pre_shared_key,
        "private_key": current_peer.private_key or "",
        "persistent_keepalive": int(current_peer.persistent_keepalive),
        "routing_template_uuid": str(current_peer.routing_template.uuid) if current_peer.routing_template else "",
        "suspended": bool(current_peer.suspended),
        "suspend_reason": current_peer.suspend_reason or "",
        "disabled_by_schedule": bool(current_peer.disabled_by_schedule),
        "enabled": bool(current_peer.enabled),
        "main_addresses": current_peer.main_addresses,
        "announced_networks": current_peer.announced_networks,
        "client_routes": current_peer.client_routes,
        "instance": f"wg{wireguard_instance.instance_id}",
        "instance_uuid": str(wireguard_instance.uuid),
    }

    return JsonResponse({"status": "success", "peer": peer_data}, status=200)


@csrf_exempt
@api_doc(
    summary="Get WireGuard status (dump) for all interfaces/peers",
    auth="Header token: <ApiKey.token>",
    methods=["POST", "GET"],
    params=[],
    returns=[
        {"status": 200, "body": {"status": "success", "message": "...", "wg0": { "...": "..." }, "cache_information": { "..." }}},
        {"status": 403, "body": {"status": "error", "error_message": "Invalid API key."}},
        {"status": 405, "body": {"status": "error", "error_message": "Method not allowed."}},
    ],
    examples={
        "get_latest_status": {
            "method": "GET",
            "json": {}
        }
    }
)
def api_v2_wireguard_status(request):
    if request.method not in ("POST", "GET"):
        return JsonResponse({"status": "error", "error_message": "Method not allowed."}, status=405)

    api_key, api_error = validate_api_key(request)
    if not api_key:
        return JsonResponse({"status": "error", "error_message": api_error}, status=403)

    data = func_get_wireguard_status()
    return JsonResponse(data)
