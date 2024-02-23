# Generated by Django 5.0.1 on 2024-02-23 15:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('wireguard', '0013_webadminsettings_current_version_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='wireguardinstance',
            name='dns_primary',
            field=models.GenericIPAddressField(default='1.1.1.1', protocol='IPv4'),
        ),
        migrations.AlterField(
            model_name='wireguardinstance',
            name='dns_secondary',
            field=models.GenericIPAddressField(blank=True, default='1.0.0.1', null=True, protocol='IPv4'),
        ),
    ]