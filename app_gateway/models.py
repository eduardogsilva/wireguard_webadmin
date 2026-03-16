import uuid

from django.db import models
from django.utils.translation import gettext_lazy as _

from gatekeeper.models import GatekeeperGroup, AuthMethod, _unique_slug


class Application(models.Model):
    name = models.SlugField(max_length=64, unique=True)
    display_name = models.CharField(max_length=128, blank=True)
    upstream = models.CharField(max_length=255, help_text=_("Upstream address, e.g.: http://10.188.18.27:3000"))
    allow_invalid_cert = models.BooleanField(default=False, help_text=_("Allow invalid or self-signed TLS certificates from the upstream"))

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def save(self, *args, **kwargs):
        if self.display_name:
            self.name = _unique_slug(Application, self.display_name, exclude_pk=self.pk)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.display_name or self.name

    class Meta:
        ordering = ['name']


class ApplicationHost(models.Model):
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name='hosts')
    hostname = models.CharField(max_length=255, unique=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def __str__(self):
        return self.hostname

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