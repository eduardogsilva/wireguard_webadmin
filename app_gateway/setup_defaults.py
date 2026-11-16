import logging

logger = logging.getLogger(__name__)


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
