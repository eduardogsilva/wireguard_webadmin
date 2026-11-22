import uuid

from django.db import models
from django.utils.translation import gettext_lazy as _

from app_gateway.dns_providers import DNS_PROVIDER_CHOICES
from cluster.models import ClusterSettings
from gatekeeper.models import GatekeeperGroup, AuthMethod, _unique_slug

RESERVED_APP_NAME = 'wireguard_webadmin'

CERTIFICATE_TYPE_CHOICES = (
    ('http_challenge', _('Trusted certificate (HTTP validation)')),
    ('dns_challenge', _('Trusted certificate (DNS validation)')),
    ('self_signed', _('Self-signed certificate')),
)

ACME_CHALLENGE_LABEL = '_acme-challenge'


def acme_challenge_base(hostname):
    """Name validated by the DNS challenge: a wildcard certificate is validated on its parent domain."""
    hostname = hostname.strip().lower().rstrip('.')
    return hostname[2:] if hostname.startswith('*.') else hostname


class DnsChallengeCredential(models.Model):
    name = models.SlugField(max_length=64, unique=True)
    display_name = models.CharField(max_length=128, blank=True)
    provider = models.CharField(max_length=32, choices=DNS_PROVIDER_CHOICES)
    credentials = models.JSONField(default=dict)
    # Zone the credential manages. When set, the challenge record of each host is a CNAME pointing to this zone.
    delegation_domain = models.CharField(max_length=253, blank=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def delegation_target(self, hostname):
        """
        Name where the challenge record of the hostname is created, or None without delegation. Hostnames inside
        the delegation domain are validated directly, since the credential already manages their zone.
        """
        if not self.delegation_domain:
            return None
        base = acme_challenge_base(hostname)
        if base == self.delegation_domain or base.endswith(f'.{self.delegation_domain}'):
            return None
        return f'{base}.{self.delegation_domain}'

    def save(self, *args, **kwargs):
        if self.display_name:
            self.name = _unique_slug(DnsChallengeCredential, self.display_name, exclude_pk=self.pk)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.display_name or self.name} ({self.get_provider_display()})"

    class Meta:
        ordering = ['name']
        verbose_name = 'DNS Challenge Credential'
        verbose_name_plural = 'DNS Challenge Credentials'


class Application(models.Model):
    name = models.SlugField(max_length=64, unique=True)
    display_name = models.CharField(max_length=128, blank=True)
    upstream = models.CharField(max_length=255, help_text=_("Upstream address, e.g.: http://10.188.18.27:3000"))
    allow_invalid_cert = models.BooleanField(default=False, help_text=_("Allow invalid or self-signed TLS certificates from the upstream"))
    serve_on_primary = models.BooleanField(default=True)
    all_workers = models.BooleanField(default=False)
    workers = models.ManyToManyField('cluster.Worker', blank=True, related_name='applications')

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def save(self, *args, **kwargs):
        if self.display_name == RESERVED_APP_NAME:
            self.name = RESERVED_APP_NAME
        elif self.display_name:
            self.name = _unique_slug(Application, self.display_name, exclude_pk=self.pk)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.display_name or self.name

    # Without an active cluster every application is served by the primary server only
    @property
    def served_by_workers(self):
        return ClusterSettings.cluster_enabled() and (self.all_workers or self.workers.exists())

    def is_served_by(self, worker):
        if not ClusterSettings.cluster_enabled():
            return worker is None
        if worker is None:
            return self.serve_on_primary
        return self.all_workers or self.workers.filter(pk=worker.pk).exists()

    class Meta:
        ordering = ['name']


class ApplicationHost(models.Model):
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name='hosts')
    hostname = models.CharField(max_length=255, unique=True)
    certificate_type = models.CharField(max_length=16, default='http_challenge', choices=CERTIFICATE_TYPE_CHOICES)
    dns_credential = models.ForeignKey(
        DnsChallengeCredential, on_delete=models.PROTECT, null=True, blank=True, related_name='hosts'
    )
    certificate_fallback = models.BooleanField(default=True)
    # Incremented to request a new ACME attempt; exported so every Caddy instance applies it
    certificate_generation = models.PositiveIntegerField(default=0)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def __str__(self):
        return self.hostname

    @property
    def certificate_label(self):
        """Short description of how the certificate is issued, used in host lists."""
        if self.certificate_type == 'self_signed':
            return _('Self-signed')
        if self.certificate_type == 'http_challenge':
            return _('HTTP validation')
        if self.dns_delegation_record:
            return _('DNS validation (delegated)')
        return _('DNS validation')

    @property
    def dns_delegation_record(self):
        """(name, target) of the CNAME required by a delegated DNS challenge, or None."""
        if self.certificate_type != 'dns_challenge' or not self.dns_credential:
            return None
        target = self.dns_credential.delegation_target(self.hostname)
        if not target:
            return None
        return f'{ACME_CHALLENGE_LABEL}.{acme_challenge_base(self.hostname)}', target

    class Meta:
        ordering = ['hostname']


class AccessPolicy(models.Model):
    name = models.SlugField(max_length=64, unique=True)
    display_name = models.CharField(max_length=128, blank=True)
    policy_type = models.CharField(max_length=32, choices=(('public', _('Public')), ('protected', _('Protected')), ('deny', _('Deny'))))
    groups = models.ManyToManyField(GatekeeperGroup, blank=True, related_name='policies')
    methods = models.ManyToManyField(AuthMethod, blank=True, related_name='policies')

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def save(self, *args, **kwargs):
        if self.display_name:
            self.name = _unique_slug(AccessPolicy, self.display_name, exclude_pk=self.pk)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.display_name or self.name} ({self.get_policy_type_display()})"

    class Meta:
        ordering = ['name']
        verbose_name = 'Access Policy'
        verbose_name_plural = 'Access Policies'


class ApplicationPolicy(models.Model):
    application = models.OneToOneField(Application, on_delete=models.CASCADE, related_name='default_policy_config')
    default_policy = models.ForeignKey(AccessPolicy, on_delete=models.PROTECT, related_name='application_defaults')

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def __str__(self):
        return f"{self.application} → default: {self.default_policy}"

    class Meta:
        verbose_name = 'Application Policy'
        verbose_name_plural = 'Application Policies'


class ApplicationRoute(models.Model):
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name='routes')
    name = models.SlugField(max_length=64)
    display_name = models.CharField(max_length=128, blank=True)
    path_prefix = models.CharField(max_length=255)
    policy = models.ForeignKey(AccessPolicy, on_delete=models.PROTECT, related_name='routes')
    order = models.PositiveIntegerField(default=0)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def save(self, *args, **kwargs):
        if self.display_name:
            self.name = _unique_slug(
                ApplicationRoute, self.display_name, exclude_pk=self.pk,
                filter_kwargs={'application': self.application},
            )
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.application} — {self.display_name or self.name} ({self.path_prefix})"

    class Meta:
        ordering = ['application', 'order', 'path_prefix']
        unique_together = [('application', 'path_prefix'), ('application', 'name')]
        verbose_name = 'Application Route'
        verbose_name_plural = 'Application Routes'