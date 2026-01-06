from django.db import models

class WireguardStatusCache(models.Model):
    cache_type = models.CharField(choices=(('master', 'Master'), ('cluster', 'Cluster')), max_length=16)
    data = models.JSONField()
    processing_time_ms = models.PositiveIntegerField()

    uuid = models.UUIDField(unique=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)