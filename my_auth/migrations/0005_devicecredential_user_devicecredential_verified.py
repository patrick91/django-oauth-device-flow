# Generated by Django 4.1.5 on 2023-01-14 18:57

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("my_auth", "0004_devicecredential_auth_time"),
    ]

    operations = [
        migrations.AddField(
            model_name="devicecredential",
            name="user",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="devicecredential",
            name="verified",
            field=models.BooleanField(default=False),
        ),
    ]
