from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.validators import RegexValidator
import random
import string


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username", "email"]


class SignUpSerializer(serializers.ModelSerializer):
    username = serializers.CharField(
        max_length=150,
        validators=[
            RegexValidator(
                regex=r"^[a-zA-Z0-9@.+-_]+$",
                message="Username must contain only letters, numbers, and @/./+/-/_ characters.",
            ),
        ],
    )
    email = serializers.EmailField(
        max_length=254, help_text="Required. Enter a valid email address."
    )
    password1 = serializers.CharField(write_only=True, style={"input_type": "password"})
    password2 = serializers.CharField(write_only=True, style={"input_type": "password"})
    suggestions = serializers.ListField(
        child=serializers.CharField(), write_only=True, required=False
    )

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2", "suggestions")

    def validate_username(self, value):
        """
        Validate that the username is unique and generate suggestions if not.
        """
        if User.objects.filter(username=value).exists():
            suggestions = self.generate_suggestions(value)
            raise serializers.ValidationError(
                {
                    "message": "This username is already taken. Please choose another.",
                    "suggestions": suggestions,
                }
            )
        return value

    def generate_suggestions(self, base_username):
        """
        Generate username suggestions.
        """
        suggestions = []
        while len(suggestions) < 4:
            sug_str = "".join(random.choices(string.ascii_letters + string.digits, k=4))
            suggestion = base_username + sug_str
            if (
                not User.objects.filter(username=suggestion).exists()
                and suggestion not in suggestions
            ):
                suggestions.append(suggestion)
        return suggestions

    def validate_email(self, value):
        """
        Validate that the email is unique.
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email address is already in use.")
        return value

    def validate_password1(self, value):
        # Validate the password using Django's validators
        print("PASSWORD")
        try:
            validate_password(value)
        except Exception as errs:
            raise serializers.ValidationError(errs)
        return value

    def validate(self, data):
        """
        Ensure both passwords match.
        """
        if data["password1"] != data["password2"]:
            raise serializers.ValidationError("The two password fields didn't match.")
        return data

    def create(self, validated_data):
        """
        Create a new user with the validated data.
        """
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password1"],
            is_active=False,
        )
        return user


# adam smith

# class RegisterSerializer(serializers.Serializer):
#     username = serializers.CharField(max_length=32)
#     password = serializers.CharField(write_only=True)
#
#     # def validate_password(self, value):
#     #     # Validate the password using Django's validators
#     #     try:
#     #         validate_password(value)
#     #     except Exception as err:
#     #         raise serializers.ValidationError(err)
#     #     return value
#
#     def validate(self, data):
#         """
#         Ensure both passwords match.
#         """
#         if data["password1"] != data["password2"]:
#             raise serializers.ValidationError("The two password fields didn't match.")
#         return data
#
#     def create(self, validated_data):
#         """
#         Create a new user with the validated data.
#         """
#         user = User.objects.create_user(
#             username=validated_data["username"],
#             email=validated_data["email"],
#             password=validated_data["password1"],
#         )
#         return user


class SignInSerializer(serializers.Serializer):
    """
    Serializer for user login, used to authenticate a user
    """

    username = serializers.CharField(max_length=32)
    password = serializers.CharField(write_only=True)


class OTPSerializer(serializers.Serializer):
    user_id = serializers.IntegerField(required=True)
    otp = serializers.CharField(max_length=6, required=True)
