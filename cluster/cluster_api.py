import json

from django.conf import settings
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.gzip import gzip_page
from django.views.decorators.http import require_GET, require_POST

from cluster.models import ClusterSettings, Worker, WorkerStatus
from cluster.sync import SECTION_NAMES, build_manifest, build_section

REPORT_STATUS_FIELDS = ('status', 'message')


def get_ip_address(request):
    ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
    if ip_address:
        ip_address = ip_address.split(',')[0].strip()
    else:
        ip_address = request.META.get('REMOTE_ADDR')
    return ip_address


def _error_response(message, status):
    return JsonResponse({'status': 'error', 'message': message}, status=status)


def get_worker(request):
    """
    Authenticate the worker from the Authorization header and update its status.
    Returns (worker, None) on success or (None, JsonResponse) when the request must be rejected.
    """
    authorization = request.headers.get('Authorization', '')
    if not authorization.startswith('Bearer '):
        return None, _error_response('Worker not found', 403)
    try:
        worker = Worker.objects.get(token=authorization[len('Bearer '):].strip())
    except (Worker.DoesNotExist, ValidationError, ValueError):
        return None, _error_response('Worker not found', 403)

    worker_status, worker_status_created = WorkerStatus.objects.get_or_create(worker=worker)
    try:
        worker_version = int(request.headers.get('X-Worker-Version', '0'))
    except ValueError:
        worker_version = 0
    worker_status.worker_version = worker_version
    worker_status.last_seen = timezone.now()
    worker_status.save(update_fields=['worker_version', 'last_seen', 'updated'])

    ip_address = get_ip_address(request)
    error_status = ''
    if worker_version < settings.CLUSTER_WORKER_MINIMUM_VERSION:
        error_status = 'update_required'
    elif worker.ip_lock and worker.ip_address and worker.ip_address != ip_address:
        error_status = 'ip_lock'
    elif not worker.enabled:
        error_status = 'worker_disabled'
    else:
        cluster_settings, cluster_settings_created = ClusterSettings.objects.get_or_create(name='cluster_settings')
        if cluster_settings.enabled and not settings.WIREGUARD_STATUS_CACHE_ENABLED:
            cluster_settings.enabled = False
            cluster_settings.save()
        if not cluster_settings.enabled:
            error_status = 'cluster_disabled'

    update_fields = []
    if not worker.ip_lock and worker.ip_address != ip_address:
        worker.ip_address = ip_address
        update_fields.append('ip_address')
    if worker.error_status != error_status:
        worker.error_status = error_status
        update_fields.append('error_status')
    if update_fields:
        worker.save(update_fields=update_fields + ['updated'])

    if error_status:
        return None, _error_response(error_status, 400)
    return worker, None


def api_legacy_cluster_status(request):
    # Workers before version 12 poll this endpoint. A 403 makes them shut down WireGuard and stop polling.
    return JsonResponse({
        'status': 'error',
        'message': 'update_required',
        'minimum_worker_version': settings.CLUSTER_WORKER_MINIMUM_VERSION,
    }, status=403)


@require_GET
def api_manifest(request):
    worker, error_response = get_worker(request)
    if error_response:
        return error_response
    return JsonResponse({
        'status': 'success',
        'worker_minimum_version': settings.CLUSTER_WORKER_MINIMUM_VERSION,
        'sections': build_manifest(worker),
    })


@gzip_page
@require_GET
def api_section(request, section_name):
    worker, error_response = get_worker(request)
    if error_response:
        return error_response
    if section_name not in SECTION_NAMES:
        return _error_response('Section not found', 404)
    return JsonResponse({'status': 'success', 'section': section_name, **build_section(section_name, worker).as_dict()})


def _clean_section_report(sections):
    cleaned_sections = {}
    for section_name, report in sections.items():
        if section_name not in SECTION_NAMES or not isinstance(report, dict):
            continue
        status = report.get('status')
        if status not in ('ok', 'error'):
            continue
        cleaned_sections[section_name] = {
            'hash': str(report.get('hash', ''))[:64],
            'status': status,
            'message': str(report.get('message', ''))[:1000],
            'updated': timezone.now().isoformat(),
        }
    return cleaned_sections


@csrf_exempt
@require_POST
def api_report(request):
    worker, error_response = get_worker(request)
    if error_response:
        return error_response
    try:
        payload = json.loads(request.body)
    except (ValueError, UnicodeDecodeError):
        return _error_response('Invalid JSON', 400)
    if not isinstance(payload, dict):
        return _error_response('Invalid JSON', 400)

    worker_status = worker.workerstatus
    update_fields = []

    if isinstance(payload.get('sections'), dict):
        section_status = dict(worker_status.section_status or {})
        section_status.update(_clean_section_report(payload['sections']))
        worker_status.section_status = section_status
        update_fields.append('section_status')

    if isinstance(payload.get('services'), dict):
        worker_status.services_status = payload['services']
        update_fields.append('services_status')

    if isinstance(payload.get('certificates'), dict):
        worker_status.certificate_status = payload['certificates']
        worker_status.certificate_status_updated = timezone.now()
        update_fields += ['certificate_status', 'certificate_status_updated']

    if isinstance(payload.get('wireguard_status'), dict):
        worker_status.wireguard_status = payload['wireguard_status']
        worker_status.wireguard_status_updated = timezone.now()
        update_fields += ['wireguard_status', 'wireguard_status_updated']

    if update_fields:
        worker_status.save(update_fields=update_fields + ['updated'])
    return JsonResponse({'status': 'success'})
