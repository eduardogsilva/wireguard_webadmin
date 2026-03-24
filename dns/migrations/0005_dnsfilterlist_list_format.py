from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dns', '0004_dnsfilterlist_recommended'),
    ]

    operations = [
        migrations.AddField(
            model_name='dnsfilterlist',
            name='list_format',
            field=models.CharField(
                choices=[('', 'Unknown'), ('hosts', 'Hosts'), ('dnsmasq', 'Dnsmasq'), ('unsupported', 'Unsupported')],
                default='',
                max_length=15,
            ),
        ),
    ]
