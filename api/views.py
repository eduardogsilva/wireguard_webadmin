import base64
import datetime
import os
import subprocess
import time
import uuid
from datetime import timedelta
from typing import Any, Dict

import pytz
import requests
from django.conf import settings
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.http import HttpResponseForbidden
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from api.models import WireguardStatusCache
from cluster.models import ClusterSettings, WorkerStatus
from scheduler.models import PeerScheduling, ScheduleProfile
from user_manager.models import AuthenticationToken, UserAcl
from vpn_invite.models import InviteSettings, PeerInvite
from wgwadmlibrary.tools import create_peer_invite, get_peer_invite_data, send_email, user_allowed_peers, \
    user_has_access_to_peer
from wireguard.models import Peer, PeerStatus, WebadminSettings, WireGuardInstance
from wireguard_tools.functions import func_reload_wireguard_interface
from wireguard_tools.views import export_wireguard_configuration


def get_api_key(api_name):
    api_key = None
    if api_name == 'api':
        api_file_path = '/etc/wireguard/api_key'
    elif api_name == 'routerfleet':
        api_file_path = '/etc/wireguard/routerfleet_key'
    elif api_name == 'rrdkey':
        api_file_path = '/app_secrets/rrdtool_key'
    elif api_name == 'cron_key':
        api_file_path = '/app_secrets/cron_key'
    else:
        return api_key

    if os.path.exists(api_file_path) and os.path.isfile(api_file_path):
        with open(api_file_path, 'r') as api_file:
            api_file_content = api_file.read().strip()
            try:
                uuid_test = uuid.UUID(api_file_content)

                if str(uuid_test) == api_file_content:
                    api_key = str(uuid_test)
            except:
                pass

    return api_key


def routerfleet_authenticate_session(request):
    AuthenticationToken.objects.filter(created__lt=timezone.now() - timezone.timedelta(minutes=1)).delete()
    authentication_token = get_object_or_404(AuthenticationToken, uuid=request.GET.get('token'))
    auth.login(request, authentication_token.user)
    authentication_token.delete()
    return redirect('/')


@require_http_methods(["GET"])
def routerfleet_get_user_token(request):
    data = {'status': '', 'message': '', 'authentication_token': ''}
    if request.GET.get('key'):
        api_key = get_api_key('routerfleet')
        if api_key and api_key == request.GET.get('key'):
            pass
        else:
            return HttpResponseForbidden()
    else:
        return HttpResponseForbidden()

    try:
        default_user_level = int(request.GET.get('default_user_level'))
        if default_user_level not in [10, 20, 30, 40, 50]:
            default_user_level = 0
    except:
        default_user_level = 0

    if request.GET.get('username'):
        user = User.objects.filter(username=request.GET.get('username')).first()

        if request.GET.get('action') == 'test':
            if UserAcl.objects.filter(user=user, user_level__gte=50).exists():
                data['status'] = 'success'
                data['message'] = 'User exists and is an administrator'
            else:
                data['status'] = 'error'
                data['message'] = f'Administrator with username {request.GET.get("username")} not found at wireguard_webadmin.'

        elif request.GET.get('action') == 'login':
            if user:
                user_acl = UserAcl.objects.filter(user=user).first()
            else:
                if default_user_level == 0:
                    data['status'] = 'error'
                    data['message'] = 'User not found'
                else:
                    user = User.objects.create_user(username=request.GET.get('username'), password=str(uuid.uuid4()))
                    user_acl = UserAcl.objects.create(user=user, user_level=default_user_level)

            if user and user_acl:
                authentication_token = AuthenticationToken.objects.create(user=user)
                data['status'] = 'success'
                data['message'] = 'User authenticated successfully'
                data['authentication_token'] = str(authentication_token.uuid)
        else:
            data['status'] = 'error'
            data['message'] = 'Invalid action'

    else:
        data['status'] = 'error'
        data['message'] = 'No username provided'

    if data['status'] == 'error':
        return JsonResponse(data, status=400)
    else:
        return JsonResponse(data)


@login_required
def peer_info(request):
    peer = get_object_or_404(Peer, uuid=request.GET.get('uuid'))
    user_acl = get_object_or_404(UserAcl, user=request.user)

    if not user_has_access_to_peer(user_acl, peer):
        raise PermissionDenied

    data = {
        'name': str(peer),
        'public_key': str(peer.public_key),
        'uuid': str(peer.uuid),
        'private_key_exists': bool(peer.private_key),
        'is_route_policy_restricted': peer.is_route_policy_restricted,
    }
    return JsonResponse(data)


@require_http_methods(["GET"])
def api_peer_list(request):
    if request.GET.get('key'):
        api_key = get_api_key('api')
        if api_key and api_key == request.GET.get('key'):
            pass
        else:
            return HttpResponseForbidden()
    else:
        return HttpResponseForbidden()
    data = {}

    requested_instance = request.GET.get('instance', 'all')
    if requested_instance == 'all':
        peer_list = Peer.objects.all()
    else:
        peer_list = Peer.objects.filter(wireguard_instance__instance_id=requested_instance.replace('wg', ''))

    for peer in peer_list:
        peer_allowed_ips = []
        for allowed_ip in peer.peerallowedip_set.all().filter(config_file='server'):
            peer_allowed_ips.append(
                {
                    'ip_address': allowed_ip.allowed_ip,
                    'priority': allowed_ip.priority,
                    'netmask': allowed_ip.netmask
                }
            )
        if f'wg{peer.wireguard_instance.instance_id}' not in data:
            data[f'wg{peer.wireguard_instance.instance_id}'] = {'peers': []}
        data[f'wg{peer.wireguard_instance.instance_id}']['peers'].append({
            'name': str(peer),
            'public_key': str(peer.public_key),
            'uuid': str(peer.uuid),
            'rrd_filename' : base64.urlsafe_b64encode(peer.public_key.encode()).decode().replace('=', '') + '.rrd',
            'last_handshake': peer.peerstatus.last_handshake.isoformat() if hasattr(peer, 'peerstatus') and peer.peerstatus.last_handshake else '',
            'allowed_ips': peer_allowed_ips,
        })
    return JsonResponse(data)


@require_http_methods(["GET"])
def api_instance_info(request):
    if request.GET.get('key'):
        api_key = get_api_key('api')
        if api_key and api_key == request.GET.get('key'):
            pass
        else:
            return HttpResponseForbidden()
    else:
        return HttpResponseForbidden()
    data = {}
    requested_instance = request.GET.get('instance', 'all')
    if requested_instance == 'all':
        instances = WireGuardInstance.objects.all()
    else:
        instances = WireGuardInstance.objects.filter(instance_id=requested_instance.replace('wg', ''))

    for instance in instances:
        data[f'wg{instance.instance_id}'] = {
            'name': instance.name,
            'instance_id': f'wg{instance.instance_id}',
            'public_key': instance.public_key,
            'listen_port': instance.listen_port,
            'hostname': instance.hostname,
            'address': instance.address,
            'netmask': instance.netmask,
            'peer_list_refresh_interval': instance.peer_list_refresh_interval,
            'dns_primary': instance.dns_primary if instance.dns_primary else '',
            'dns_secondary': instance.dns_secondary if instance.dns_secondary else '',
            'uuid': str(instance.uuid),
        }
    return JsonResponse(data)


def func_process_wireguard_status() -> Dict[str, Any]:
    command = "wg show all dump"

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        return {"message": stderr, "status": "error"}

    data: Dict[str, Dict[str, Dict[str, Any]]] = {}

    # wg dump format is tab-separated.
    # There are two kinds of lines:
    # - Interface line: interface \t private_key \t public_key \t listen_port \t fwmark
    # - Peer line: interface \t peer_public_key \t preshared_key \t endpoint \t allowed_ips \t latest_handshake \t transfer_rx \t transfer_tx \t persistent_keepalive
    for line in stdout.strip().split("\n"):
        parts = line.split("\t")
        if len(parts) < 5:
            continue

        interface = parts[0]

        # Peer lines are expected to have at least 9 fields
        if len(parts) < 9:
            # interface line, ignore
            continue

        peer_public_key = parts[1]
        endpoint = parts[3]
        allowed_ips_raw = parts[4]
        latest_handshake = parts[5]
        transfer_rx = parts[6]
        transfer_tx = parts[7]

        if interface not in data:
            data[interface] = {}

        data[interface][peer_public_key] = {
            "allowed-ips": [ip for ip in allowed_ips_raw.split(",") if ip] if allowed_ips_raw else [],
            "latest-handshakes": latest_handshake or "",
            "transfer": {"tx": int(transfer_tx or 0), "rx": int(transfer_rx or 0)},
            "endpoints": endpoint or "",
        }

    return data


def func_apply_enhanced_filter(data: dict, user_acl: UserAcl):
    # Remove peers and instances that are not allowed for the user
    if user_acl.enable_enhanced_filter:
        pass
    else:
        pass
    return data


def func_get_wireguard_status(cache_previous: int = 0):
    if settings.WIREGUARD_STATUS_CACHE_ENABLED:
        if ClusterSettings.objects.filter(name='cluster_settings', enabled=True).exists():
            cache_objects = WireguardStatusCache.objects.filter(cache_type='cluster').order_by('-created')
        else:
            cache_objects = WireguardStatusCache.objects.filter(cache_type='master').order_by('-created')

        if cache_previous > 0:
            try:
                cache_entry = cache_objects[cache_previous]
            except IndexError:
                cache_entry = None
        else:
            cache_entry = cache_objects.first()

        if cache_entry:
            data = cache_entry.data
            data['cache_information'] = {
                'processing_time_ms': cache_entry.processing_time_ms,
                'created': cache_entry.created.isoformat(),
                'cache_type': cache_entry.cache_type,
                'cache_hit': True,
                'cache_enabled': True,
                'cache_uuid': str(cache_entry.uuid),
                'cache_previous_requested': cache_previous,
            }
            data['status'] = 'success'
            data['message'] = 'WireGuard status retrieved from cache'
        else:
            data = {
                'status': 'error',
                'message': 'No cache entry found',
                'cache_information': {
                    'cache_hit': False,
                    'cache_enabled': True,
                    'cache_previous_requested': cache_previous,
                }
            }
    else:
        data = func_process_wireguard_status()
        data['cache_information'] = {
            'cache_hit': False,
            'cache_enabled': False,
        }
        data['status'] = 'success'
        data['message'] = 'WireGuard status retrieved without cache'
    return data


def _latest_handshake_as_int(peer_info) -> int:
    try:
        return int(peer_info.get("latest-handshakes", 0))
    except:
        return 0


def func_concatenate_cluster_wireguard_status_cache() -> None:
    start_time = time.monotonic()

    cache_entries = []
    combined_data: Dict[str, Dict[str, Dict[str, Any]]] = {}

    master_cache = (
        WireguardStatusCache.objects.filter(cache_type="master")
        .order_by("-created")
        .first()
    )
    if master_cache and isinstance(master_cache.data, dict):
        cache_entries.append({"source_name": "master", "source_uuid": "", "data": master_cache.data,})

    worker_statuses = (WorkerStatus.objects.filter(
        worker__enabled=True, wireguard_status_updated__gt=timezone.now() - timedelta(minutes=10)
    ).select_related("worker").all())

    for ws in worker_statuses:
        cache_entries.append(
            {
                "source_name": f"worker_{ws.worker.name}",
                "source_uuid": str(ws.worker.uuid),
                "data": ws.wireguard_status or {},
            }
        )

    for entry in cache_entries:
        source_name = entry["source_name"]
        source_uuid = entry["source_uuid"]
        data = entry.get("data") or {}

        if not isinstance(data, dict):
            continue

        for interface, peers in data.items():
            if not isinstance(peers, dict):
                continue

            combined_data.setdefault(interface, {})

            for peer_key, peer_info in peers.items():
                if not isinstance(peer_info, dict):
                    continue

                peer_info_copy = dict(peer_info)
                peer_info_copy["source_name"] = source_name
                peer_info_copy["source_uuid"] = source_uuid

                if peer_key not in combined_data[interface]:
                    combined_data[interface][peer_key] = peer_info_copy
                    continue

                existing_peer = combined_data[interface][peer_key]

                new_hs = _latest_handshake_as_int(peer_info_copy)
                old_hs = _latest_handshake_as_int(existing_peer)

                if new_hs > old_hs:
                    combined_data[interface][peer_key] = peer_info_copy

    processing_time_ms = int((time.monotonic() - start_time) * 1000)
    WireguardStatusCache.objects.create(data=combined_data, processing_time_ms=processing_time_ms, cache_type="cluster")
    return


def cron_refresh_wireguard_status_cache(request):
    api_key = get_api_key('cron_key')
    if api_key and api_key == request.GET.get('cron_key'):
        pass
    else:
        return HttpResponseForbidden()

    data = {'status': 'success'}
    WireguardStatusCache.objects.filter(created__lt=timezone.now() - timezone.timedelta(seconds=settings.WIREGUARD_STATUS_CACHE_MAX_AGE)).delete()

    if not settings.WIREGUARD_STATUS_CACHE_ENABLED:
        return JsonResponse(data)
    start_time = time.monotonic()
    wireguard_status_data = func_process_wireguard_status()
    end_time = time.monotonic()
    processing_time_ms = int((end_time - start_time) * 1000)
    WireguardStatusCache.objects.create(data=wireguard_status_data, processing_time_ms=processing_time_ms, cache_type='master')
    if ClusterSettings.objects.filter(name='cluster_settings', enabled=True).exists():
        func_concatenate_cluster_wireguard_status_cache()
    return JsonResponse(data)


def cron_calculate_peer_schedules(request):
    api_key = get_api_key('cron_key')
    if api_key and api_key == request.GET.get('cron_key'):
        pass
    else:
        return HttpResponseForbidden()

    data = {
        'status': 'success',
        'updated_records': 0,
        'skipped_records': 0,
    }

    peer_scheduling_queryset = (
        PeerScheduling.objects
        .select_related('peer', 'profile')
        .filter(
            profile__active=True,
            peer__suspended=False,
        )
        .filter(
            Q(next_scheduled_enable_at__isnull=True) |
            Q(next_scheduled_disable_at__isnull=True)
        )
    )

    if not peer_scheduling_queryset.exists():
        return JsonResponse(data)

    distinct_profile_ids = list(
        peer_scheduling_queryset.values_list('profile_id', flat=True).distinct()
    )

    schedule_profiles = (
        ScheduleProfile.objects
        .filter(id__in=distinct_profile_ids, active=True)
        .prefetch_related('time_interval')
    )

    profile_next_dates_cache = {}

    for schedule_profile in schedule_profiles:
        next_dates = schedule_profile.next_dates
        profile_next_dates_cache[schedule_profile.id] = (
            next_dates.get('enable'),
            next_dates.get('disable'),
        )

    peer_schedulings_to_update = []

    for peer_scheduling in peer_scheduling_queryset.iterator(chunk_size=500):
        next_enable_at, next_disable_at = profile_next_dates_cache.get(
            peer_scheduling.profile_id,
            (None, None)
        )

        if not next_enable_at or not next_disable_at:
            data['skipped_records'] += 1
            continue

        peer_scheduling.next_scheduled_enable_at = next_enable_at
        peer_scheduling.next_scheduled_disable_at = next_disable_at

        peer_schedulings_to_update.append(peer_scheduling)

    if peer_schedulings_to_update:
        PeerScheduling.objects.bulk_update(
            peer_schedulings_to_update,
            ['next_scheduled_enable_at', 'next_scheduled_disable_at'],
            batch_size=500
        )
        data['updated_records'] = len(peer_schedulings_to_update)

    return JsonResponse(data)


def cron_peer_scheduler(request):
    api_key = get_api_key('cron_key')
    if api_key and api_key == request.GET.get('cron_key'):
        pass
    else:
        return HttpResponseForbidden()

    now = timezone.now()
    data = {
        'status': 'success',
        'message': '',
        'scheduled_peers_disabled': 0,
        'scheduled_peers_enabled': 0,
        'scheduled_peers_suspended': 0,
        'scheduled_peers_unsuspended': 0,
    }

    interfaces = set()

    pending_schedulings = (
        PeerScheduling.objects
        .select_related('peer', 'peer__wireguard_instance')
        .filter(
            Q(next_scheduled_enable_at__lte=now) |
            Q(next_scheduled_disable_at__lte=now) |
            Q(next_manual_suspend_at__lte=now) |
            Q(next_manual_unsuspend_at__lte=now)
        )
    )

    for peer_scheduling in pending_schedulings:
        if peer_scheduling.next_scheduled_enable_at and peer_scheduling.next_scheduled_enable_at <= now:
            data['scheduled_peers_enabled'] += 1
            peer_scheduling.next_scheduled_enable_at = None
            peer_scheduling.peer.disabled_by_schedule = False
            interfaces.add(peer_scheduling.peer.wireguard_instance)

        if peer_scheduling.next_scheduled_disable_at and peer_scheduling.next_scheduled_disable_at <= now:
            data['scheduled_peers_disabled'] += 1
            peer_scheduling.next_scheduled_disable_at = None
            peer_scheduling.peer.disabled_by_schedule = True
            interfaces.add(peer_scheduling.peer.wireguard_instance)

        if peer_scheduling.next_manual_unsuspend_at and peer_scheduling.next_manual_unsuspend_at <= now:
            data['scheduled_peers_unsuspended'] += 1
            peer_scheduling.next_manual_unsuspend_at = None
            peer_scheduling.peer.suspended = False
            peer_scheduling.peer.suspend_reason = ''
            interfaces.add(peer_scheduling.peer.wireguard_instance)

        if peer_scheduling.next_manual_suspend_at and peer_scheduling.next_manual_suspend_at <= now:
            data['scheduled_peers_suspended'] += 1
            peer_scheduling.next_manual_suspend_at = None
            peer_scheduling.peer.suspended = True
            peer_scheduling.peer.suspend_reason = peer_scheduling.manual_suspend_reason
            interfaces.add(peer_scheduling.peer.wireguard_instance)

        peer_scheduling.peer.save()
        peer_scheduling.save()

    errors = []
    for wireguard_instance in interfaces:
        export_wireguard_configuration(wireguard_instance)
        ok, msg = func_reload_wireguard_interface(wireguard_instance)
        if not ok:
            errors.append(f"wg{wireguard_instance.instance_id} - {msg}")

    if errors:
        data['status'] = 'error'
        data['message'] = " | ".join(errors)
        return JsonResponse(data, status=500)

    return JsonResponse(data, status=200)


@require_http_methods(["GET"])
def wireguard_status(request):
    user_acl = None
    enhanced_filter = False
    filter_peer_list = []

    try:
        cache_previous = int(request.GET.get('cache_previous', 0))
    except:
        cache_previous = 0

    if request.user.is_authenticated:
        user_acl = get_object_or_404(UserAcl, user=request.user)
        if user_acl.enable_enhanced_filter and user_acl.peer_groups.count() > 0:
            enhanced_filter = True
    elif request.GET.get('key'):
        api_key = get_api_key('api')
        if api_key and api_key == request.GET.get('key'):
            pass
        else:
            return HttpResponseForbidden()
    elif request.GET.get('rrdkey'):
        api_key = get_api_key('rrdkey')
        if api_key and api_key == request.GET.get('rrdkey'):
            pass
        else:
            return HttpResponseForbidden()
    else:
        return HttpResponseForbidden()

    data = func_get_wireguard_status(cache_previous)
    return JsonResponse(data)


@require_http_methods(["GET"])
def legacy_wireguard_status(request):
    user_acl = None
    enhanced_filter = False
    filter_peer_list = []

    if request.user.is_authenticated:
        user_acl = get_object_or_404(UserAcl, user=request.user)
        if user_acl.enable_enhanced_filter and user_acl.peer_groups.count() > 0:
            enhanced_filter = True
    elif request.GET.get('key'):
        api_key = get_api_key('api')
        if api_key and api_key == request.GET.get('key'):
            pass
        else:
            return HttpResponseForbidden()
    elif request.GET.get('rrdkey'):
        api_key = get_api_key('rrdkey')
        if api_key and api_key == request.GET.get('rrdkey'):
            pass
        else:
            return HttpResponseForbidden()
    else:
        return HttpResponseForbidden()

    if enhanced_filter:
        for server_instance in WireGuardInstance.objects.all():
            for peer in user_allowed_peers(user_acl, server_instance):
                if peer.public_key not in filter_peer_list:
                    filter_peer_list.append(peer.public_key)

    commands = {
        'latest-handshakes': "wg show all latest-handshakes | expand | tr -s ' '",
        'allowed-ips': "wg show all allowed-ips | expand | tr -s ' '",
        'transfer': "wg show all transfer | expand | tr -s ' '",
        'endpoints': "wg show all endpoints | expand | tr -s ' '",
    }

    output = {}

    for key, command in commands.items():
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            return JsonResponse({'error': stderr}, status=400)

        current_interface = None
        for line in stdout.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 3:
                interface, peer, value = parts[0], parts[1], " ".join(parts[2:])
                current_interface = interface
            elif len(parts) == 2 and current_interface:
                peer, value = parts
            else:
                continue

            if interface not in output:
                output[interface] = {}
            if enhanced_filter and peer not in filter_peer_list:
                continue
            if peer not in output[interface]:
                output[interface][peer] = {
                    'allowed-ips': [],
                    'latest-handshakes': '',
                    'transfer': {'tx': 0, 'rx': 0},
                    'endpoints': '',
                }

            if key == 'allowed-ips':
                output[interface][peer]['allowed-ips'].append(value)
            elif key == 'transfer':
                rx, tx = value.split()[-2:]
                output[interface][peer]['transfer'] = {'tx': int(tx), 'rx': int(rx)}
            elif key == 'endpoints':
                output[interface][peer]['endpoints'] = value
            else:
                output[interface][peer][key] = value

    return JsonResponse(output)


@require_http_methods(["GET"])
def cron_update_peer_latest_handshake(request):
    api_key = get_api_key('cron_key')
    if api_key and api_key == request.GET.get('cron_key'):
        pass
    else:
        return HttpResponseForbidden()

    command = "wg show all latest-handshakes | expand | tr -s ' '"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        return JsonResponse({'error': stderr}, status=400)
    #debug_information = []
    for line in stdout.strip().split('\n'):
        parts = line.split()
        if len(parts) < 3:
            continue
        interface, peer_public_key, latest_handshake = parts[0], parts[1], parts[2]
        latest_handshake_timestamp = int(latest_handshake)

        if latest_handshake_timestamp > 0:
            last_handshake_time = datetime.datetime.fromtimestamp(latest_handshake_timestamp, tz=pytz.utc)
            #debug_information.append(f'Last handshake for {peer_public_key} is {last_handshake_time}')
            peer = Peer.objects.filter(public_key=peer_public_key).first()
            if peer:
                #debug_information.append(f'Peer found: {peer.public_key}')
                peer_status, created = PeerStatus.objects.get_or_create(
                    peer=peer,
                    defaults={'last_handshake': last_handshake_time}
                )
                if not created:
                    if peer_status.last_handshake != last_handshake_time:
                        #debug_information.append(f'Updating last_handshake for {peer.public_key} to {last_handshake_time}')
                        peer_status.last_handshake = last_handshake_time
                        peer_status.save()
                    #else:
                    #    debug_information.append(f'No changes for {peer.public_key}')

    return JsonResponse({'status': 'success'})


def cron_check_updates(request):
    api_key = get_api_key('cron_key')
    if api_key and api_key == request.GET.get('cron_key'):
        pass
    else:
        return HttpResponseForbidden()

    webadmin_settings, webadmin_settings_created = WebadminSettings.objects.get_or_create(name='webadmin_settings')
    if webadmin_settings.last_checked is None or timezone.now() > (webadmin_settings.last_checked + datetime.timedelta(hours=1)):
        try:
            version = settings.WIREGUARD_WEBADMIN_VERSION / 10000
            url = f'https://updates.eth0.com.br/api/check_updates/?app=wireguard_webadmin&version={version}'
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            
            if 'update_available' in data:
                webadmin_settings.update_available = data['update_available']
                
                if data['update_available']:
                    webadmin_settings.latest_version = float(data['current_version']) * 10000
                    
                webadmin_settings.last_checked = timezone.now()
                webadmin_settings.save()

                response_data = {
                    'update_available': webadmin_settings.update_available,
                    'latest_version': webadmin_settings.latest_version,
                    'current_version': settings.WIREGUARD_WEBADMIN_VERSION,
                }
                return JsonResponse(response_data)
            
        except Exception as e:
            webadmin_settings.update_available = False
            webadmin_settings.save()
            return JsonResponse({'update_available': False})
    
    return JsonResponse({'update_available': webadmin_settings.update_available})


@login_required
def api_peer_invite(request):
    PeerInvite.objects.filter(invite_expiration__lt=timezone.now()).delete()
    user_acl = get_object_or_404(UserAcl, user=request.user)
    invite_settings = InviteSettings.objects.filter(name='default_settings').first()
    peer_invite = PeerInvite.objects.none()

    if not invite_settings:
        data = {'status': 'error', 'message': 'VPN Invite not configured'}
        return JsonResponse(data, status=400)

    data = {
        'status': '', 'message': '', 'invite_data': {},
        'whatsapp_enabled': invite_settings.invite_whatsapp_enabled,
        'email_enabled': invite_settings.invite_email_enabled,
    }

    if user_acl.user_level < invite_settings.required_user_level:
        data['status'] = 'error'
        data['message'] = 'Permission denied'
        return JsonResponse(data, status=403)

    if request.GET.get('peer'):
        peer = get_object_or_404(Peer, uuid=request.GET.get('peer'))
        if not user_has_access_to_peer(user_acl, peer):
            data['status'] = 'error'
            data['message'] = 'Permission denied'
            return JsonResponse(data, status=403)
        peer_invite = PeerInvite.objects.filter(peer=peer).first()
        if not peer_invite:
            peer_invite = create_peer_invite(peer, invite_settings)

    elif request.GET.get('invite'):
        peer_invite = get_object_or_404(PeerInvite, uuid=request.GET.get('invite'))
        if request.GET.get('action') == 'refresh':
            peer_invite.invite_expiration = timezone.now() + datetime.timedelta(minutes=invite_settings.invite_expiration)
            peer_invite.save()
        elif request.GET.get('action') == 'delete':
            peer_invite.delete()
            data['status'] = 'success'
            data['message'] = 'Invite deleted'
            return JsonResponse(data)

    if peer_invite:
        data['status'] = 'success'
        data['message'] = ''
        data['invite_data'] = get_peer_invite_data(peer_invite, invite_settings)

        if request.GET.get('action') == 'email':
            data['status'], data['message'] = send_email(request.GET.get('address'), data['invite_data']['email_subject'], data['invite_data']['email_body'])
            if data['status'] == 'success':
                return JsonResponse(data)
            else:
                return JsonResponse(data, status=400)
    else:
        if request.GET.get('action') == 'email':
            data['status'] = 'error'
            data['message'] = 'Invite not found'
            return JsonResponse(data)
    return JsonResponse(data, status=200)