# Generated by Django 5.0.2 on 2024-03-04 11:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('firewall', '0010_alter_firewallrule_firewall_chain'),
    ]

    operations = [
        migrations.AddField(
            model_name='firewallsettings',
            name='last_firewall_reset',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
