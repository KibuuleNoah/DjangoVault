from django.contrib.auth.models import User
from rest_framework.throttling import BaseThrottle
from django.utils import timezone
from .models import OTPUser


class OTPRequestThrottle(BaseThrottle):
    def allow_request(self, request, view):
        try:
            user_id = request.data["user_id"]
        except KeyError:
            return False

        user = User.objects.get(id=user_id)
        if not user:
            return False

        otp_user = OTPUser.objects.filter(user=user).first()

        if not otp_user:
            return False

        now = timezone.now()

        if request.method == "GET":
            try:
                request.data["otp_resend_token"]
            except KeyError:
                return False

            # Check if the last get request was made within the 200-second interval
            if (
                otp_user.last_get_request_time
                and (now - otp_user.last_get_request_time).total_seconds() < 200
            ):
                return False

        elif request.method == "POST":
            # Check if the last post request was made within the 200-second interval
            if (
                otp_user.last_post_request_time
                and (now - otp_user.last_post_request_time).total_seconds() < 200
            ):
                return False

        # Check if the request count exceeds 5 requests per day
        if otp_user.request_count >= 6:
            # Reset request count if the last get request was on a different day
            if otp_user.last_get_request_time.date() != now.date():
                otp_user.request_count = 0
            else:
                return False

        # Update the OTPUser record
        if request.method == "GET":
            otp_user.last_get_request_time = now
        elif request.method == "POST":
            otp_user.last_post_request_time = now

        otp_user.request_count += 1
        otp_user.save()
        return True

    def wait(self):
        return 200
