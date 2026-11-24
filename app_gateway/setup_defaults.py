import ipaddress
import logging

from django.conf import settings

logger = logging.getLogger(__name__)

INTERNAL_WEBADMIN_HOSTNAME = 'wireguard-webadmin'


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname.strip('[]'))
    except ValueError:
        return False
    return True


def get_webadmin_hostnames():
    # Mirrors the host selection made by containers/caddy/export_wireguard_webadmin_config.py
    hostnames = []
    for hostname in settings.ALLOWED_HOSTS:
        hostname = hostname.strip().lower()
        if not hostname or hostname == INTERNAL_WEBADMIN_HOSTNAME or hostname in hostnames:
            continue
        if is_ip_address(hostname) or hostname == 'localhost' or hostname.endswith('.localhost'):
            continue
        hostnames.append(hostname)
    return hostnames


def sync_webadmin_hosts(application):
    from app_gateway.models import ApplicationHost

    webadmin_hostnames = get_webadmin_hostnames()

    removed_hosts = application.hosts.exclude(hostname__in=webadmin_hostnames)
    for application_host in removed_hosts:
        logger.info("Removed WireGuard WebAdmin host: %s", application_host.hostname)
    removed_hosts.delete()

    for hostname in webadmin_hostnames:
        existing_host = ApplicationHost.objects.filter(hostname=hostname).select_related('application').first()
        if existing_host:
            if existing_host.application_id != application.id:
                logger.warning(
                    "Hostname '%s' is used by WireGuard WebAdmin but is also assigned to application '%s'. "
                    "Remove it from that application to manage its certificate settings.",
                    hostname, existing_host.application
                )
            continue
        ApplicationHost.objects.create(application=application, hostname=hostname)
        logger.info("Added WireGuard WebAdmin host: %s", hostname)


def create_default_entries(**kwargs):
    from app_gateway.models import AccessPolicy, Application, ApplicationPolicy, RESERVED_APP_NAME

    # Default access policies
    public_policy = AccessPolicy.objects.filter(policy_type='public').order_by('created').first()
    if not public_policy:
        public_policy = AccessPolicy.objects.create(policy_type='public', display_name='Public')
        logger.info("Created default AccessPolicy: Public")

    if not AccessPolicy.objects.filter(policy_type='deny').exists():
        AccessPolicy.objects.create(policy_type='deny', display_name='Deny')
        logger.info("Created default AccessPolicy: Deny")

    # Reserved wireguard_webadmin application
    app, created = Application.objects.get_or_create(
        display_name=RESERVED_APP_NAME,
        defaults={'upstream': 'http://wireguard-webadmin:8000'},
    )
    if created:
        logger.info("Created default Application: %s", RESERVED_APP_NAME)
        if not ApplicationPolicy.objects.filter(application=app).exists():
            ApplicationPolicy.objects.create(application=app, default_policy=public_policy)
            logger.info("Assigned default policy 'Public' to application '%s'", RESERVED_APP_NAME)

    sync_webadmin_hosts(app)
