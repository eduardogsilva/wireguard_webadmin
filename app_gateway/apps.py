from django.apps import AppConfig


class AppGatewayConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app_gateway'

    def ready(self):
        from django.db.models.signals import post_migrate
        from app_gateway.setup_defaults import create_default_entries
        post_migrate.connect(create_default_entries, sender=self)
