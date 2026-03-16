from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('gatekeeper', '0007_remove_authmethod_totp_before_auth_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='authmethod',
            name='session_expiration_minutes',
            field=models.PositiveIntegerField(default=720, help_text='Session expiration time in minutes (only for Local Password and OIDC)'),
        ),
    ]
