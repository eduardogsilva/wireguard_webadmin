# Generated by Django 5.0.1 on 2024-02-17 17:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('wireguard', '0007_remove_wireguardinstance_persistent_keepalive'),
    ]

    operations = [
        migrations.AddField(
            model_name='wireguardinstance',
            name='dns_primary',
            field=models.GenericIPAddressField(default='1.1.1.1', protocol='IPv4', unique=False),
        ),
        migrations.AddField(
            model_name='wireguardinstance',
            name='dns_secondary',
            field=models.GenericIPAddressField(blank=True, default='1.0.0.1', null=True, protocol='IPv4', unique=False),
        ),
        migrations.AddField(
            model_name='wireguardinstance',
            name='peer_list_refresh_interval',
            field=models.IntegerField(default=20),
        ),
    ]
