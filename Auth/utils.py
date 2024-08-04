from django.core.mail import send_mail
from django.conf import settings
from django_otp.plugins.otp_totp.models import TOTPDevice


def create_otp_device(user):
    device = TOTPDevice.objects.create(user=user, name="Default", confirmed=True)
    return device


def send_welcome_email(user_email):
    subject = "Welcome to MySite"
    message = "Thank you for signing up for our service."
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [user_email]
    send_mail(subject, message, from_email, recipient_list)
