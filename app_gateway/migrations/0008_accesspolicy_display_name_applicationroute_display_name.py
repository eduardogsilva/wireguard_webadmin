from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app_gateway', '0007_application_allow_invalid_cert'),
    ]

    operations = [
        migrations.AddField(
            model_name='accesspolicy',
            name='display_name',
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddField(
            model_name='applicationroute',
            name='display_name',
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AlterField(
            model_name='applicationroute',
            name='name',
            field=models.SlugField(max_length=64),
        ),
    ]
