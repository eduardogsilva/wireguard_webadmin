from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app_gateway', '0006_alter_accesspolicy_policy_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='application',
            name='allow_invalid_cert',
            field=models.BooleanField(default=False, help_text='Allow invalid or self-signed TLS certificates from the upstream'),
        ),
    ]
