from django.urls import path
from .views import SignInView, SignUpView, OTPConfirmView, HomeView, LogOutView

urlpatterns = [
    path("signup/", SignUpView.as_view(), name="auth-signup"),
    path("signin/", SignInView.as_view(), name="auth-signin"),
    path("otp/", OTPConfirmView.as_view(), name="otp-confirm"),
    path("home/", HomeView.as_view(), name="home"),
    path("logout/", LogOutView.as_view(), name="auth-logout"),
]
