# Generated by Django 4.2.11 on 2024-05-06 10:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0007_alter_historicalperformancemodel_average_response_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='historicalperformancemodel',
            name='average_response_time',
            field=models.TimeField(default=None, null=True),
        ),
    ]
