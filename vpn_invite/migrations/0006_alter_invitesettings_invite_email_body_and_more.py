# Generated by Django 5.1.5 on 2025-02-28 00:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vpn_invite', '0005_alter_invitesettings_download_1_label'),
    ]

    operations = [
        migrations.AlterField(
            model_name='invitesettings',
            name='invite_email_body',
            field=models.TextField(default='Here is your WireGuard VPN invite link: {invite_url}\n\nThis link expires in {expire_minutes} minutes.'),
        ),
        migrations.AlterField(
            model_name='invitesettings',
            name='invite_text_body',
            field=models.TextField(default='Here is your WireGuard VPN invite link: {invite_url}\n\nThis link expires in {expire_minutes} minutes.'),
        ),
        migrations.AlterField(
            model_name='invitesettings',
            name='invite_whatsapp_body',
            field=models.TextField(default='Here is your WireGuard VPN invite link: {invite_url}\n\nThis link expires in {expire_minutes} minutes.'),
        ),
    ]
