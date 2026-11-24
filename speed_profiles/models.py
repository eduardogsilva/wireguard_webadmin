import uuid
from decimal import Decimal

from django.db import models


def mbit_to_kbit(value):
    return int((Decimal(value) * 1000).to_integral_value())


def megabytes_to_bytes(value):
    return int((Decimal(value) * 1_000_000).to_integral_value())


class SpeedProfile(models.Model):
    """Bandwidth limit applied to each peer that uses the profile. Empty limits mean no limit in that direction."""
    name = models.CharField(max_length=64, unique=True)
    # Mbit/s. Download is the traffic that reaches the peer, upload the traffic the peer sends.
    download_limit = models.DecimalField(max_digits=9, decimal_places=3, blank=True, null=True)
    upload_limit = models.DecimalField(max_digits=9, decimal_places=3, blank=True, null=True)
    # MB that may pass at full speed before the limit applies. Empty means the automatic minimum.
    download_burst = models.DecimalField(max_digits=9, decimal_places=3, blank=True, null=True)
    upload_burst = models.DecimalField(max_digits=9, decimal_places=3, blank=True, null=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

    @staticmethod
    def _format(value):
        # 10.000 -> "10", 0.500 -> "0.5"
        return f'{Decimal(value).normalize():f}'

    @property
    def download_display(self):
        return self._format(self.download_limit) if self.download_limit else ''

    @property
    def upload_display(self):
        return self._format(self.upload_limit) if self.upload_limit else ''

    @property
    def download_burst_display(self):
        return self._format(self.download_burst) if self.download_burst else ''

    @property
    def upload_burst_display(self):
        return self._format(self.upload_burst) if self.upload_burst else ''

    @property
    def summary(self):
        """Short description used in peer pages, e.g. "↓ 10 Mbit/s · ↑ 5 Mbit/s"."""
        parts = []
        if self.download_limit:
            parts.append(f'↓ {self.download_display} Mbit/s')
        if self.upload_limit:
            parts.append(f'↑ {self.upload_display} Mbit/s')
        return ' · '.join(parts)

    def config_comment(self):
        """Settings written to the WireGuard configuration of each peer, read when the limits are applied."""
        values = []
        if self.download_limit:
            values.append(f'download_kbit={mbit_to_kbit(self.download_limit)}')
            if self.download_burst:
                values.append(f'download_burst={megabytes_to_bytes(self.download_burst)}')
        if self.upload_limit:
            values.append(f'upload_kbit={mbit_to_kbit(self.upload_limit)}')
            if self.upload_burst:
                values.append(f'upload_burst={megabytes_to_bytes(self.upload_burst)}')
        return ' '.join(values)
