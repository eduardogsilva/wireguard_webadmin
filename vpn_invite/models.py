from django.db import models
from wireguard.models import Peer
import uuid


class InviteSettings(models.Model):
    name = models.CharField(max_length=16, default='default_settings', unique=True)
    default_password = models.CharField(max_length=32, default='', blank=True, null=True)
    enforce_random_password = models.BooleanField(default=True)
    required_user_level = models.PositiveIntegerField(default=50, choices=(
        (20, 'View Only User'), (30, 'Peer Manager'), (40, 'Wireguard Manager'), (50, 'Administrator'),
    ))
    random_password_length = models.IntegerField(default=6)
    random_password_complexity = models.CharField(
        max_length=22, default='letters_digits', choices=(
            ('letters_digits_special', 'Letters, Digits, Special Characters'),
            ('letters_digits', 'Letters, Digits'), ('letters', 'Letters'), ('digits', 'Digits')
        )
    )
    invite_expiration = models.IntegerField(default=30) # minutes
    download_1_label = models.CharField(max_length=32, default='iOS', blank=True, null=True)
    download_2_label = models.CharField(max_length=32, default='Android', blank=True, null=True)
    download_3_label = models.CharField(max_length=32, default='Windows', blank=True, null=True)
    download_4_label = models.CharField(max_length=32, default='macOS', blank=True, null=True)
    download_5_label = models.CharField(max_length=32, default='Desktop', blank=True, null=True)
    download_1_icon = models.CharField(max_length=32, default='fab fa-app-store-ios', blank=True, null=True)
    download_2_icon = models.CharField(max_length=32, default='fab fa-google-play', blank=True, null=True)
    download_3_icon = models.CharField(max_length=32, default='fab fa-windows', blank=True, null=True)
    download_4_icon = models.CharField(max_length=32, default='fab fa-apple', blank=True, null=True)
    download_5_icon = models.CharField(max_length=32, default='fas fa-desktop', blank=True, null=True)
    download_1_url = models.URLField(default='https://apps.apple.com/us/app/wireguard/id1441195209', blank=True, null=True)
    download_2_url = models.URLField(default='https://play.google.com/store/apps/details?id=com.wireguard.android', blank=True, null=True)
    download_3_url = models.URLField(default='https://download.wireguard.com/windows-client/wireguard-installer.exe', blank=True, null=True)
    download_4_url = models.URLField(default='https://apps.apple.com/us/app/wireguard/id1451685025', blank=True, null=True)
    download_5_url = models.URLField(default='https://www.wireguard.com/install/', blank=True, null=True)
    download_1_enabled = models.BooleanField(default=True)
    download_2_enabled = models.BooleanField(default=True)
    download_3_enabled = models.BooleanField(default=True)
    download_4_enabled = models.BooleanField(default=True)
    download_5_enabled = models.BooleanField(default=True)
    download_instructions = models.TextField(default='Download the WireGuard app for your device using one of the links below. After installation, you can scan the QR code or download the configuration file to import on your device.')

    invite_url = models.URLField(default='')

    invite_text_body = models.TextField(default='Here is your WireGuard VPN invite link: {invite_url}\n\nThis link expires in {expire_minutes} minutes.')

    invite_email_subject = models.CharField(max_length=64, default='WireGuard VPN Invite', blank=True, null=True)
    invite_email_body = models.TextField(default='Here is your WireGuard VPN invite link: {invite_url}\n\nThis link expires in {expire_minutes} minutes.')
    invite_email_enabled = models.BooleanField(default=True)

    invite_whatsapp_body = models.TextField(default='Here is your WireGuard VPN invite link: {invite_url}\n\nThis link expires in {expire_minutes} minutes.')
    invite_whatsapp_enabled = models.BooleanField(default=True)

    uuid = models.UUIDField(default=uuid.uuid4, editable=False)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)


class PeerInvite(models.Model):
    peer = models.ForeignKey(Peer, on_delete=models.CASCADE)
    invite_password = models.CharField(max_length=32, default='')
    invite_expiration = models.DateTimeField()

    uuid = models.UUIDField(default=uuid.uuid4, editable=False)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)