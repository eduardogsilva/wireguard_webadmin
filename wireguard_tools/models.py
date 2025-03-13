import uuid

from django.db import models


class EmailSettings(models.Model):
    name = models.CharField(default='email_settings', max_length=20, unique=True)
    smtp_username = models.CharField(max_length=100, blank=True, null=True)
    smtp_password = models.CharField(max_length=100, blank=True, null=True)
    smtp_host = models.CharField(max_length=100, blank=True, null=True)
    smtp_port = models.IntegerField(default=587)
    smtp_encryption = models.CharField(default='tls', choices=(('ssl', 'SSL'), ('tls', 'TLS'), ('none', 'None (Insecure)'), ('noauth', 'No authentication (Insecure)')), max_length=6)
    smtp_from_address = models.EmailField(blank=True, null=True)
    enabled = models.BooleanField(default=True)

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
