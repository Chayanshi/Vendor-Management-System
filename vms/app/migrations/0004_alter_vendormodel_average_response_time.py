# Generated by Django 4.2.11 on 2024-05-05 17:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0003_alter_vendormodel_average_response_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vendormodel',
            name='average_response_time',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
    ]
