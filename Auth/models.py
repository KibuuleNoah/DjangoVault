from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone
from rest_framework.exceptions import Throttled
from django_otp.oath import TOTP, totp
from django_otp.util import random_hex
from uuid import uuid4


class OTPUser(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    key = models.CharField(max_length=80, default=random_hex(64))
    first_seen = models.BooleanField(default=True)
    request_count = models.PositiveIntegerField(default=0)
    last_get_request_time = models.DateTimeField(null=True, blank=True)
    last_post_request_time = models.DateTimeField(null=True, blank=True)
    step = 200
    digits = 6

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @property
    def generate_otp(self) -> int:
        totp = TOTP(key=str(self.key).encode(), step=self.step, digits=self.digits)
        return totp.token()

    def verify_otp(self, token: int) -> bool:
        totp = TOTP(key=str(self.key).encode(), step=self.step, digits=self.digits)
        return totp.verify(token)


class OTPResendRefrence(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=80, default=str(uuid4()))
    issue_time = models.DateTimeField(default=timezone.now)


# from django.db import models
# from django.contrib.auth.models import User
# from django_otp.oath import TOTP
# from django_otp.util import random_hex


# class OTPUser(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     key = models.CharField(max_length=80, default=random_hex(64))
#     first_seen = models.BooleanField(default=True)
#
#     # throttling_failure_count = models.PositiveIntegerField()
#     # throttling_failure_timestamp = models.DateTimeField(null=True, blank=True)
#     # created_at = models.DateTimeField(null=True, blank=True)
#     # last_used_at = models.DateTimeField(null=True, blank=True)
#
#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         self.step = 200
#         self.digits = 6
#
#     @property
#     def generate_otp(self) -> int:
#         totp = TOTP(key=str(self.key).encode(), step=self.step, digits=self.digits)
#         return totp.token()
#
#     def verify_otp(self, token: int) -> bool:
#         totp = TOTP(key=str(self.key).encode(), step=self.step, digits=self.digits)
#         return totp.verify(token)
