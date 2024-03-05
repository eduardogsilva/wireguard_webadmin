# Generated by Django 5.0.2 on 2024-02-28 15:37

import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('firewall', '0002_redirectrule_masquerade_source_and_more'),
        ('wireguard', '0018_wireguardinstance_legacy_firewall'),
    ]

    operations = [
        migrations.CreateModel(
            name='FirewallSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('global', models.CharField(max_length=6, unique=True)),
                ('default_forward_policy', models.CharField(choices=[('accept', 'ACCEPT'), ('reject', 'REJECT'), ('drop', 'DROP')], default='accept', max_length=6)),
                ('default_output_policy', models.CharField(choices=[('accept', 'ACCEPT'), ('reject', 'REJECT'), ('drop', 'DROP')], default='accept', max_length=6)),
                ('allow_peer_to_peer', models.BooleanField(default=True)),
                ('allow_instance_to_instance', models.BooleanField(default=True)),
                ('wan_interface', models.CharField(default='eth0', max_length=12)),
            ],
        ),
        migrations.CreateModel(
            name='ForwardRule',
            fields=[
                ('description', models.CharField(blank=True, max_length=100, null=True)),
                ('firewall_chain', models.CharField(choices=[('FORWARD', 'FORWARD'), ('OUTPUT', 'OUTPUT'), ('POSTROUTING', 'POSTROUTING (nat)')], default='FORWARD', max_length=12)),
                ('in_interface', models.CharField(blank=True, default='', max_length=12, null=True)),
                ('out_interface', models.CharField(blank=True, default='', max_length=12, null=True)),
                ('source_ip', models.GenericIPAddressField(blank=True, null=True, protocol='IPv4')),
                ('source_netmask', models.PositiveIntegerField(choices=[(8, '/8 (255.0.0.0)'), (9, '/9 (255.128.0.0)'), (10, '/10 (255.192.0.0)'), (11, '/11 (255.224.0.0)'), (12, '/12 (255.240.0.0)'), (13, '/13 (255.248.0.0)'), (14, '/14 (255.252.0.0)'), (15, '/15 (255.254.0.0)'), (16, '/16 (255.255.0.0)'), (17, '/17 (255.255.128.0)'), (18, '/18 (255.255.192.0)'), (19, '/19 (255.255.224.0)'), (20, '/20 (255.255.240.0)'), (21, '/21 (255.255.248.0)'), (22, '/22 (255.255.252.0)'), (23, '/23 (255.255.254.0)'), (24, '/24 (255.255.255.0)'), (25, '/25 (255.255.255.128)'), (26, '/26 (255.255.255.192)'), (27, '/27 (255.255.255.224)'), (28, '/28 (255.255.255.240)'), (29, '/29 (255.255.255.248)'), (30, '/30 (255.255.255.252)'), (32, '/32 (255.255.255.255)')], default=32)),
                ('source_peer_include_networks', models.BooleanField(default=False)),
                ('not_source', models.BooleanField(default=False)),
                ('destination_ip', models.GenericIPAddressField(blank=True, null=True, protocol='IPv4')),
                ('destination_netmask', models.PositiveIntegerField(choices=[(8, '/8 (255.0.0.0)'), (9, '/9 (255.128.0.0)'), (10, '/10 (255.192.0.0)'), (11, '/11 (255.224.0.0)'), (12, '/12 (255.240.0.0)'), (13, '/13 (255.248.0.0)'), (14, '/14 (255.252.0.0)'), (15, '/15 (255.254.0.0)'), (16, '/16 (255.255.0.0)'), (17, '/17 (255.255.128.0)'), (18, '/18 (255.255.192.0)'), (19, '/19 (255.255.224.0)'), (20, '/20 (255.255.240.0)'), (21, '/21 (255.255.248.0)'), (22, '/22 (255.255.252.0)'), (23, '/23 (255.255.254.0)'), (24, '/24 (255.255.255.0)'), (25, '/25 (255.255.255.128)'), (26, '/26 (255.255.255.192)'), (27, '/27 (255.255.255.224)'), (28, '/28 (255.255.255.240)'), (29, '/29 (255.255.255.248)'), (30, '/30 (255.255.255.252)'), (32, '/32 (255.255.255.255)')], default=32)),
                ('destination_peer_include_networks', models.BooleanField(default=False)),
                ('not_destination', models.BooleanField(default=False)),
                ('protocol', models.CharField(blank=True, choices=[('', 'all'), ('tcp', 'TCP'), ('udp', 'UDP'), ('both', 'TCP+UDP'), ('icmp', 'ICMP')], default='', max_length=4, null=True)),
                ('destination_port', models.CharField(blank=True, max_length=11, null=True)),
                ('state_new', models.BooleanField(default=False)),
                ('state_related', models.BooleanField(default=False)),
                ('state_established', models.BooleanField(default=False)),
                ('state_invalid', models.BooleanField(default=False)),
                ('state_untracked', models.BooleanField(default=False)),
                ('not_state', models.BooleanField(default=False)),
                ('rule_action', models.CharField(choices=[('accept', 'ACCEPT'), ('reject', 'REJECT'), ('drop', 'DROP'), ('masquerade', 'MASQUERADE')], default='accept', max_length=10)),
                ('sort_order', models.PositiveIntegerField(default=0)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('destination_peer', models.ManyToManyField(blank=True, related_name='forward_rules_as_destination', to='wireguard.peer')),
                ('source_peer', models.ManyToManyField(blank=True, related_name='forward_rules_as_source', to='wireguard.peer')),
                ('wireguard_instance', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='wireguard.wireguardinstance')),
            ],
        ),
    ]