# Generated by Django 5.0.2 on 2024-02-29 13:02

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('firewall', '0003_firewallsettings_forwardrule'),
        ('wireguard', '0018_wireguardinstance_legacy_firewall'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='ForwardRule',
            new_name='FirewallRule',
        ),
    ]
