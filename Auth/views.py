from django.shortcuts import render, reverse
from django.urls import reverse_lazy
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView, View
from django.contrib.auth import login, authenticate
from django.contrib.auth.models import User
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LogoutView
from django_otp.plugins.otp_totp.models import TOTPDevice

from Auth.utils import send_welcome_email, create_otp_device
from .forms import LoginForm, SignUpForm, OTPForm


# from django.shortcuts import render, redirect
# from django.contrib import messages
# from django.views import View
# from django_otp import devices_for_user
#
# class OTPVerifyView(View):
#     def get(self, request, *args, **kwargs):
#         return render(request, 'otp_verify.html')
#
#     def post(self, request, *args, **kwargs):
#         otp = request.POST.get('otp')
#         user = request.user
#         for device in devices_for_user(user):
#             if device.verify_token(otp):
#                 device.throttle_reset()
#                 request.session['otp_verified'] = True
#                 return redirect('some_secure_view')
#         messages.error(request, 'Invalid OTP')
#         return render(request, 'otp_verify.html')
class HomeView(LoginRequiredMixin, TemplateView):
    login_url = reverse_lazy("auth-login")
    template_name = "home.html"

    def get(self, request, *args, **kwargs):
        # device = TOTPDevice.objects.filter(user=request.user).first()
        device = create_otp_device(request.user)
        # Generate OTP
        otp = device
        print("OTP", otp)
        # Verify OTP
        # is_valid = device.verify_token(otp)

        return super().get(request, *args, **kwargs)


class LogOutView(LoginRequiredMixin, LogoutView):
    login_url = reverse_lazy("auth-login")
    next_page = reverse_lazy("auth-login")


class SignUpView(FormView):
    template_name = "signup.html"
    form_class = SignUpForm
    success_url = reverse_lazy("home")  # Redirect to home after successful signup

    def form_valid(self, form):
        # Save the user
        user = form.save()
        user.refresh_from_db()  # Load the profile instance created by the signal
        user.save()

        # Authenticate and login the user
        raw_password = form.cleaned_data.get("password1")
        user = authenticate(username=user.username, password=raw_password)
        if user is not None:
            login(self.request, user)

        return super().form_valid(form)

    def form_invalid(self, form):
        # Get username suggestions if the username is already taken
        suggestions = form.get_suggestions()
        return self.render_to_response(
            self.get_context_data(form=form, suggestions=suggestions)
        )


class SignInView(FormView):
    form_class = LoginForm
    template_name = "signin.html"
    success_url = reverse_lazy("home")  # Redirect to home after successful signup

    def form_valid(self, form):
        username = form.cleaned_data["username"]
        password = form.cleaned_data["password"]

        user_exists = User.objects.filter(username=username).first()

        if user_exists:
            user = authenticate(
                self.request,
                username=username,
                password=password,
            )
            if user:
                login(self.request, user)
                return super().form_valid(form)
            return self.render_to_response(
                self.get_context_data(
                    username=username, message="Wrong password for that user name"
                )
            )
        return self.render_to_response(
            self.get_context_data(message="User name doesn't exists")
        )


class OTPConfirmView(View):
    template_name = "otp-confirm.html"
    form_class = OTPForm

    def get(self, request, *args, **kwargs):
        form = self.form_class()
        return render(request, self.template_name, {"form": form})

    # def post(self, request, *args, **kwargs):
    #     form = self.form_class(request.POST)
    #     if form.is_valid():
    #         otp = form.cleaned_data['otp']
    #         try:
    #             otp_object = OTP.objects.get(code=otp, user=request.user, is_verified=False)
    #             time_diff = timezone.now() - otp_object.created_at
    #             # Assuming OTP is valid for 10 minutes
    #             if time_diff.total_seconds() > 600:
    #                 messages.error(request, "OTP has expired.")
    #             else:
    #                 otp_object.is_verified = True
    #                 otp_object.save()
    #                 messages.success(request, "OTP verified successfully.")
    #                 return redirect('success_page')  # Redirect to a success page or dashboard
    #         except OTP.DoesNotExist:
    #             messages.error(request, "Invalid OTP.")
    #
    #     return render(request, self.template_name, {'form': form})
