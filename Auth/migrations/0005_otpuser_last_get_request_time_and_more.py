# Generated by Django 5.0.7 on 2024-08-07 10:25

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("Auth", "0004_otpuser_first_seen_alter_otpuser_key"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="otpuser",
            name="last_get_request_time",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="otpuser",
            name="last_post_request_time",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="otpuser",
            name="request_count",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name="otpuser",
            name="key",
            field=models.CharField(
                default="695c613a1902e0f34137da76aef7d63c70d89f5ddd4da7358e3eff378a638db84be8a7516347d5cf25257cdaf4d25a8551cb3844c5e0b0dce47e9a8cee7d7508",
                max_length=80,
            ),
        ),
        migrations.CreateModel(
            name="OTPResendRefrence",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "token",
                    models.CharField(
                        default="60f943a8-3872-4100-9966-19d92484750d", max_length=80
                    ),
                ),
                ("issue_time", models.DateTimeField(default=django.utils.timezone.now)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]
