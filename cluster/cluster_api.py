import glob
import os

from django.http import JsonResponse
from django.utils import timezone

from .models import ClusterSettings, Worker, WorkerStatus


def get_ip_address(request):
    ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
    if ip_address:
        ip_address = ip_address.split(',')[0]
    else:
        ip_address = request.META.get('REMOTE_ADDR')
    return ip_address


def get_worker(request):
    min_worker_version = 1
    success = True
    ip_address = get_ip_address(request)
    token = request.GET.get('token', '')
    try:
        worker = Worker.objects.get(token=token)
    except:
        return None, False

    worker_status, created = WorkerStatus.objects.get_or_create(worker=worker)
    try:
        worker_config_version = int(request.GET.get('worker_config_version'))
        worker_version = int(request.GET.get('worker_version'))
    except:
        worker.error_status = 'missing_version'
        worker.save()
        return worker, False

    if worker.error_status == 'missing_version':
        worker.error_status = ''
        worker.save()

    if worker_version < min_worker_version:
        worker.error_status = 'update_required'
        worker.save()
        return worker, False
    if worker.error_status == 'update_required':
        worker.error_status = ''
        worker.save()

    if worker_status.config_version != worker_config_version:
        worker_status.config_version = worker_config_version
    if worker_status.worker_version != worker_version:
        worker_status.worker_version = worker_version
    worker_status.last_seen = timezone.now()
    worker_status.save()
    
    if not worker.ip_address:
        worker.ip_address = ip_address
        worker.save()

    if worker.ip_lock:
        if worker.ip_address == ip_address:
            if worker.error_status == 'ip_lock':
                worker.error_status = ''
                worker.save()
        else:
            worker.error_status = 'ip_lock'
            worker.save()
            success = False
    else:
        if worker.ip_address != ip_address:
            worker.ip_address = ip_address
            worker.save()
    
    if worker.enabled:
        if worker.error_status == 'worker_disabled':
            worker.error_status = ''
            worker.save()
    else:
        worker.error_status = 'worker_disabled'
        worker.save()
        success = False

    cluster_settings, created = ClusterSettings.objects.get_or_create(name='cluster_settings')
    if cluster_settings.enabled:
        if worker.error_status == 'cluster_disabled':
            worker.error_status = ''
            worker.save()
    else:
        worker.error_status = 'cluster_disabled'
        worker.save()
        success = False

    return worker, success


def api_get_worker_config_files(request):
    worker, success = get_worker(request)
    if worker:
        if worker.error_status or not success:
            data = {'status': 'error', 'message': worker.error_status}
            return JsonResponse(data, status=400)
    else:
        data = {'status': 'error', 'message': 'Worker not found'}
        return JsonResponse(data, status=403)

    config_files = (
        glob.glob('/etc/wireguard/wg*.conf') +
        glob.glob('/etc/wireguard/wg-firewall.sh')
    )

    files = {}

    for path in config_files:
        filename = os.path.basename(path)
        with open(path, 'r') as f:
            files[filename] = f.read()
    cluster_settings, created = ClusterSettings.objects.get_or_create(name='cluster_settings')
    return JsonResponse(
        {
            'status': 'success',
            'files': files,
            'cluster_settings': {
                'enabled': cluster_settings.enabled,
                'primary_enable_wireguard': cluster_settings.primary_enable_wireguard,
                'stats_sync_interval': cluster_settings.stats_sync_interval,
                'stats_cache_interval': cluster_settings.stats_cache_interval,
                'cluster_mode': cluster_settings.cluster_mode,
                'restart_mode': cluster_settings.restart_mode,
                'config_version': cluster_settings.config_version,
            },
        },
        status=200
    )


def api_cluster_status(request):
    worker, success = get_worker(request)
    if worker:
        if worker.error_status or not success:
            data = {'status': 'error', 'message': worker.error_status}
            return JsonResponse(data, status=400)
    else:
        data = {'status': 'error', 'message': 'Worker not found'}
        return JsonResponse(data, status=403)
    cluster_settings, created = ClusterSettings.objects.get_or_create(name='cluster_settings')
    data = {
        'status': 'success',
        'worker_error_status': worker.error_status,
        'cluster_settings': {
            'enabled': cluster_settings.enabled,
            'primary_enable_wireguard': cluster_settings.primary_enable_wireguard,
            'stats_sync_interval': cluster_settings.stats_sync_interval,
            'stats_cache_interval': cluster_settings.stats_cache_interval,
            'cluster_mode': cluster_settings.cluster_mode,
            'restart_mode': cluster_settings.restart_mode,
            'config_version': cluster_settings.config_version,
        },
    }

    return JsonResponse(data, status=200)
