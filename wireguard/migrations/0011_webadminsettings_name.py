# Generated by Django 5.0.1 on 2024-02-22 18:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('wireguard', '0010_remove_webadminsettings_webadmin_settings'),
    ]

    operations = [
        migrations.AddField(
            model_name='webadminsettings',
            name='name',
            field=models.CharField(default='webadmin_settings', max_length=20, unique=True),
        ),
    ]
