import uuid

from django.db import models
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _


def _unique_slug(model_class, display_name, exclude_pk=None, slug_field='name', filter_kwargs=None):
    base = slugify(display_name) or 'item'
    slug = base
    counter = 1
    qs = model_class.objects.all()
    if exclude_pk:
        qs = qs.exclude(pk=exclude_pk)
    if filter_kwargs:
        qs = qs.filter(**filter_kwargs)
    while qs.filter(**{slug_field: slug}).exists():
        slug = f"{base}-{counter}"
        counter += 1
    return slug


class AuthMethod(models.Model):
    name = models.SlugField(max_length=64, unique=True)
    display_name = models.CharField(max_length=128, blank=True)
    auth_type = models.CharField(max_length=32, choices=(
        ('local_password', _('Local Password')),
        ('totp', _('One-Time Password (TOTP)')),
        ('oidc', _('OpenID Connect (OIDC)')),
        ('ip_address', _('IP Address List'))
    ))

    # TOTP-specific fields
    totp_secret = models.CharField(max_length=255, blank=True, help_text=_("Shared/global TOTP secret key"))

    # Session expiration (Local Password and OIDC only)
    session_expiration_minutes = models.PositiveIntegerField(
        default=720,
        help_text=_("Session expiration time in minutes")
    )

    # OIDC-specific fields
    oidc_provider = models.CharField(max_length=64, blank=True)
    oidc_client_id = models.CharField(max_length=255, blank=True)
    oidc_client_secret = models.CharField(max_length=255, blank=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def save(self, *args, **kwargs):
        if self.display_name:
            self.name = _unique_slug(AuthMethod, self.display_name, exclude_pk=self.pk)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.display_name or self.name} ({self.get_auth_type_display()})"

    class Meta:
        ordering = ['name']


class AuthMethodAllowedDomain(models.Model):
    auth_method = models.ForeignKey(AuthMethod, on_delete=models.CASCADE, related_name='allowed_domains', limit_choices_to={'auth_type': 'oidc'})
    domain = models.CharField(max_length=255)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def __str__(self):
        return self.domain

    class Meta:
        unique_together = [('auth_method', 'domain')]


class AuthMethodAllowedEmail(models.Model):
    auth_method = models.ForeignKey(AuthMethod, on_delete=models.CASCADE, related_name='allowed_emails', limit_choices_to={'auth_type': 'oidc'})
    email = models.EmailField()

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def __str__(self):
        return self.email

    class Meta:
        unique_together = [('auth_method', 'email')]


class GatekeeperUser(models.Model):
    username = models.SlugField(max_length=64, unique=True)
    email = models.EmailField(blank=True)
    password = models.CharField(blank=True, max_length=250, help_text=_("Password for local authentication (leave blank if not using)"))
    totp_secret = models.CharField(max_length=255, blank=True, help_text=_("Per-user TOTP secret key"))

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def __str__(self):
        return self.username

    class Meta:
        ordering = ['username']
        verbose_name = 'Gatekeeper User'
        verbose_name_plural = 'Gatekeeper Users'


class GatekeeperGroup(models.Model):
    name = models.SlugField(max_length=64, unique=True)
    display_name = models.CharField(max_length=128, blank=True)
    users = models.ManyToManyField(GatekeeperUser, blank=True, related_name='groups')

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def save(self, *args, **kwargs):
        if self.display_name:
            self.name = _unique_slug(GatekeeperGroup, self.display_name, exclude_pk=self.pk)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.display_name or self.name

    class Meta:
        ordering = ['name']
        verbose_name = 'Gatekeeper Group'
        verbose_name_plural = 'Gatekeeper Groups'


class GatekeeperIPAddress(models.Model):
    auth_method = models.ForeignKey(
        AuthMethod, on_delete=models.CASCADE, related_name='ip_addresses',
        limit_choices_to={'auth_type': 'ip_address'}
    )
    address = models.GenericIPAddressField()
    prefix_length = models.PositiveSmallIntegerField(null=True, blank=True)
    action = models.CharField(max_length=8, choices=(('allow', _('Allow')), ('deny', _('Deny'))), default='allow')
    description = models.CharField(max_length=255, blank=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    def __str__(self):
        prefix = f"/{self.prefix_length}" if self.prefix_length is not None else ""
        return f"{self.address}{prefix} ({self.get_action_display()})"

    class Meta:
        ordering = ['address']
        unique_together = [('auth_method', 'address', 'prefix_length')]
        verbose_name = 'IP Address'
        verbose_name_plural = 'IP Addresses'