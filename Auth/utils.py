from django.core.mail import send_mail
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from uuid import uuid4
from Auth.models import OTPResendRefrence, OTPUser


def send_otp_email(user_email, otp):
    subject = "DJANGO VAULT OTP VERIFICATION"
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [user_email]

    # Message content
    message_content = (
        "Thank you for signing up for our service. To complete your registration, "
        "please use the following OTP code:\n\n"
        f"OTP Code: {otp}\n\n"
        "This code is valid for a limited time. If you did not request this, please ignore this email.\n"
        "For security reasons, do not share your OTP with anyone.\n\n"
        "Best regards,\n"
        "The Django Vault Team"
    )

    plain_message = message_content
    html_message = f"""
    <html>
        <body>
            <h2>OTP Verification</h2>
            <p>Thank you for signing up for our service. To complete your registration, please use the following OTP code:</p>
            <h2 style="color: #2C3E50;">{otp}</h2>
            <p>This code is valid for a limited time. If you did not request this, please ignore this email.</p>
            <p>For security reasons, do not share your OTP with anyone.</p>
            <p>Best regards, <br/> The Django Vault Team</p>
        </body>
    </html>
    """

    send_mail(
        subject, plain_message, from_email, recipient_list, html_message=html_message
    )

    # Optionally, return the OTP code if you need to store it for verification
    # return otp_code


def blacklist_token(token):
    try:
        token = RefreshToken(token)
        token.blacklist()
    except Exception as e:
        # Handle errors if token cannot be blacklisted
        print(f"Error blacklisting token: {e}")


def regenerate_otp(user, otp_resend_token: str) -> tuple[int, str]:
    now = timezone.now()
    secs = 60
    mins = 30

    otp_user = OTPUser.objects.filter(user=user).first()
    otp_resend_ref = OTPResendRefrence.objects.filter(user=user).first()

    if not otp_user or not otp_resend_ref:
        return 0, "OTP User Not Found"

    if (now - otp_resend_ref.issue_time).total_seconds() > (mins * secs):
        return 0, "OTP Resend Token Expired,Just Login Again"

    if otp_resend_ref.token != otp_resend_token:
        return 0, "Invalid OTP Resend Token"

    otp_resend_ref.token = str(uuid4())
    otp_resend_ref.save()

    return otp_user.generate_otp, otp_resend_ref.token


def send_email(user_email):
    subject = "DJANGO VAULT OTP VERIFICATION"
    message = "Thank you for signing up for our service."
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [user_email]
    send_mail(subject, message, from_email, recipient_list)
