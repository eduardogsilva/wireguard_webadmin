from django.utils.translation import gettext_lazy as _

# Every provider listed here must also be compiled into the Caddy image
# (see containers/caddy/Dockerfile-caddy). Field names must match the
# subdirectives accepted by the provider's Caddy DNS module, and the optional
# pattern should mirror the module's own validation, since an invalid value
# prevents Caddy from loading the configuration.
DNS_PROVIDERS = {
    'cloudflare': {
        'label': 'Cloudflare',
        'fields': [
            {
                'name': 'api_token',
                'label': _('API Token'),
                'secret': True,
                'pattern': r'^(cf(ut|at)_[A-Za-z0-9_-]{32,256}|[A-Za-z0-9_-]{35,50})$',
            },
        ],
    },
}

DNS_PROVIDER_CHOICES = [(provider, provider_data['label']) for provider, provider_data in DNS_PROVIDERS.items()]
