import ipaddress

from django.db import migrations


def set_self_signed_for_ip_hosts(apps, schema_editor):
    ApplicationHost = apps.get_model('app_gateway', 'ApplicationHost')
    for application_host in ApplicationHost.objects.all():
        try:
            ipaddress.ip_address(application_host.hostname.strip('[]'))
        except ValueError:
            continue
        application_host.certificate_type = 'self_signed'
        application_host.save(update_fields=['certificate_type'])


class Migration(migrations.Migration):

    dependencies = [
        ('app_gateway', '0009_dns_challenge_credentials'),
    ]

    operations = [
        migrations.RunPython(set_self_signed_for_ip_hosts, migrations.RunPython.noop),
    ]
