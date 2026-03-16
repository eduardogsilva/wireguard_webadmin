from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('gatekeeper', '0010_alter_gatekeeperuser_email'),
    ]

    operations = [
        migrations.AddField(
            model_name='authmethod',
            name='display_name',
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddField(
            model_name='gatekeepergroup',
            name='display_name',
            field=models.CharField(blank=True, max_length=128),
        ),
    ]
