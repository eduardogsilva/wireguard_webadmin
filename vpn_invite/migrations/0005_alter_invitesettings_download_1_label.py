# Generated by Django 5.1.5 on 2025-02-27 19:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vpn_invite', '0004_alter_invitesettings_required_user_level'),
    ]

    operations = [
        migrations.AlterField(
            model_name='invitesettings',
            name='download_1_label',
            field=models.CharField(blank=True, default='iOS', max_length=32, null=True),
        ),
    ]
