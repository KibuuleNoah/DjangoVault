from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from string import ascii_letters, digits

# from django import forms
# from django.contrib.auth.models import User
# from django.core.validators import RegexValidator
# import random
#
# class CustomUserCreationForm(forms.ModelForm):
#     username = forms.CharField(
#         max_length=150,
#         required=True,
#         validators=[
#             RegexValidator(
#                 regex=r'^[a-zA-Z0-9@.+-_]+$',
#                 message='Username must contain only letters, numbers, and @/./+/-/_ characters.',
#             ),
#         ]
#     )
#     password = forms.CharField(widget=forms.PasswordInput)
#     suggestions = forms.CharField(widget=forms.HiddenInput(), required=False)
#
#     class Meta:
#         model = User
#         fields = ('username', 'password')
#
#     def clean_username(self):
#         username = self.cleaned_data.get('username')
#         if User.objects.filter(username=username).exists():
#             self.suggestions = self.generate_suggestions(username)
#             self.add_error('username', 'This username is already taken. Please choose another.')
#             return username
#         return username
#
#     def generate_suggestions(self, username):
#         suggestions = []
#         while len(suggestions) < 4:
#             suggestion = f"{username}_{random.randint(1, 9999)}"
#             if not User.objects.filter(username=suggestion).exists() and suggestion not in suggestions:
#                 suggestions.append(suggestion)
#         return suggestions
#
#     def get_suggestions(self):
#         return getattr(self, 'suggestions', [])

# from django import forms
# from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.validators import RegexValidator
import random


class SignUpForm(UserCreationForm):
    email = forms.EmailField(
        max_length=254,
        required=True,
        help_text="Required. Enter a valid email address.",
    )
    suggestions = []

    class Meta:
        model = User
        fields = (
            "username",
            "email",
            "password1",
            "password2",
        )
        # Define the validators for the username field here
        field_classes = {"username": forms.CharField}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].validators.append(
            RegexValidator(
                regex=r"^[a-zA-Z0-9@.+-_]+$",
                message="Username must contain only letters, numbers, and @/./+/-/_ characters.",
            )
        )

    def clean_username(self):
        username = self.cleaned_data.get("username")
        if User.objects.filter(username=username).exists():
            self.suggestions = self.generate_suggestions(username)
            return username
        return username

    def generate_suggestions(self, base_username):
        suggestions = []
        while len(suggestions) < 4:
            sug_str = "".join(random.choices(ascii_letters + digits, k=4))
            suggestion = base_username + sug_str
            if (
                not User.objects.filter(username=suggestion).exists()
                and suggestion not in suggestions
            ):
                suggestions.append(suggestion)
        return suggestions

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("This email address is already in use.")
        return email

    def get_suggestions(self):
        return self.suggestions


# class SignUpForm(UserCreationForm):
#     email = forms.EmailField(
#         max_length=254,
#         required=True,
#         help_text="Required. Enter a valid email address.",
#     )
#
#     class Meta:
#         model = User
#         fields = (
#             "username",
#             "email",
#             "password1",
#             "password2",
#         )
#
#     def clean_email(self):
#         email = self.cleaned_data.get("email")
#         if User.objects.filter(email=email).exists():
#             raise forms.ValidationError("This email address is already in use.")
#         return email


class LoginForm(forms.Form):
    """
    User login form that is used to authenticate a user
    """

    username = forms.CharField(max_length=32)
    password = forms.CharField(widget=forms.PasswordInput)


class OTPForm(forms.Form):
    otp = forms.CharField(max_length=6, required=True, label="Enter OTP")
