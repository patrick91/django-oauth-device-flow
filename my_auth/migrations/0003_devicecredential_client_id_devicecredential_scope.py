# Generated by Django 4.1.5 on 2023-01-14 16:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("my_auth", "0002_devicecredential"),
    ]

    operations = [
        migrations.AddField(
            model_name="devicecredential",
            name="client_id",
            field=models.CharField(db_index=True, default=1, max_length=48),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="devicecredential",
            name="scope",
            field=models.TextField(default="", null=True),
        ),
    ]