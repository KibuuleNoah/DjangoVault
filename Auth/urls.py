from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import SignUpView, SignInView, SignOutView, OTPView, Home

urlpatterns = [
    path("", Home.as_view(), name="home"),
    path("signup/", SignUpView.as_view(), name="auth-signup"),
    path("signin/", SignInView.as_view(), name="auth-signin"),
    path("signout/", SignOutView.as_view(), name="auth-signout"),
    path("otp/", OTPView.as_view(), name="auth-otp"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
]
