from uuid import uuid4
from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.crypto import secrets
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from .utils import regenerate_otp, send_otp_email
from Auth.models import OTPResendRefrence, OTPUser
from .throttling import OTPRequestThrottle
from .serializers import (
    OTPSerializer,
    SignInSerializer,
    SignUpSerializer,
    UserSerializer,
)


class Home(APIView):
    def get(self, request):
        return Response({"message": "Hello World"})


class SignUpView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # fields required by the serializer ["username", "email", "password1", "password2"]
        serializer = SignUpSerializer(data=request.data)
        if serializer.is_valid():
            # if sent user data is valid, it's saved
            new_user = serializer.save()
            # create an OTP user from the newly created user
            otp_user = OTPUser.objects.create(user=new_user)
            otp_resend_ref = OTPResendRefrence.objects.create(user=new_user)
            # generate otp that will activate the newly create account
            otp = otp_user.generate_otp

            return Response(
                {
                    "message": "OTP sent to email.",
                    "user_id": new_user.id,
                    "otp": otp,
                    "otp_resend_token": otp_resend_ref.token,
                },
                status=status.HTTP_200_OK,
            )
            # temp_email = "noahkibuule3@gmail.com"
            # send an otp via email to the provided user email
            # send_otp_email(temp_email, otp)
            # response back with the username and email
            # return Response(serializer.data, status=status.HTTP_201_CREATED)
        # response with the errors occuried
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class SignInView(APIView): ...
class SignInView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SignInSerializer(data=request.data)

        if not serializer.is_valid():
            # if the serializer is not valid
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        username = request.data.get("username")
        password = request.data.get("password")

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response(
                {"error": "User does not exist."}, status=status.HTTP_404_NOT_FOUND
            )

        if not user.check_password(password):
            return Response(
                {"error": "Incorrect password."}, status=status.HTTP_400_BAD_REQUEST
            )

        # Generate and send OTP
        otp_user = OTPUser.objects.filter(user=user).first()
        otp_resend_ref = OTPResendRefrence.objects.filter(user=user).first()

        if not otp_user:
            # if the user has not been registered for OTP yet
            return Response(
                {"error": "OTP user Not Found"}, status=status.HTTP_404_NOT_FOUND
            )

        otp = otp_user.generate_otp
        otp_resend_ref.token = str(uuid4())
        otp_resend_ref.save()

        return Response(
            {
                "message": "OTP sent to email.",
                "user_id": user.id,
                "otp": otp,
                "otp_resend_token": otp_resend_ref.token,
            },
            status=status.HTTP_200_OK,
        )
        # send_otp_email(user.email, otp)

        # return Response({"message": "OTP sent to email."}, status=status.HTTP_200_OK)


# class SignOutView(APIView): ...


class SignOutView(APIView):
    def post(self, request):
        refresh_token = request.data.get("refresh_token")
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"message": "Successfully logged out."}, status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class OTPView(APIView):
    throttle_classes = [OTPRequestThrottle]
    permission_classes = [AllowAny]

    def get(self, request):
        user = User.objects.get(id=request.data["user_id"])
        res_int, res_str = regenerate_otp(user, request.data["otp_resend_token"])
        if res_int == 0:
            return Response({"error": res_str}, status=status.HTTP_400_BAD_REQUEST)
        return Response(
            {"otp": res_int, "otp_resend_token": res_str},
            status=status.HTTP_201_CREATED,
        )

    def post(self, request):
        serializer = OTPSerializer(data=request.data)

        if not serializer.is_valid():
            # if the serializer is not valid
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.get(id=int(serializer.data["user_id"]))
        if not user:
            # if the user doesn't exist
            return Response({"user": "NOT FOUND"}, status=status.HTTP_404_NOT_FOUND)

        otp_token = serializer.data["otp"]
        otp_user = OTPUser.objects.filter(user=user).first()

        if not otp_user:
            # if the user has not been registered for OTP yet
            return Response(
                {"error": "OTP user Not Found"}, status=status.HTTP_404_NOT_FOUND
            )

        is_otp_valid = otp_user.verify_otp(int(otp_token))

        if not is_otp_valid:
            # if OTP provided by user is Invalid
            return Response(
                {"error": "Invalid OTP"},
                status=status.HTTP_403_FORBIDDEN,
            )

        if otp_user.first_seen:
            # if it's the first time for user to get OTP
            # activate user account
            user.is_active = True
            # mark the user as seen already
            otp_user.first_seen = False
            # save to data base
            user.save()
            otp_user.save()

        # user_credentials = {"username", p}
        tokens = self.get_tokens(user)
        return Response(tokens, status=status.HTTP_201_CREATED)

    def get_tokens(self, user):
        # manually generate refresh and access_token tokens
        refresh = RefreshToken.for_user(user)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }


# class OTP(APIView):
#     permission_classes = [AllowAny]
#
#     def get(self, request):
#         # user = User.objects.get_by_natural_key("tristar3")
#         # serialized_user = UserSerializer(user)
#         # if serialized_user.is_valid():
#         #     return Response({"user": serialized_user.data}, status=status.HTTP_200_OK)
#         # return Response(serialized_user.errors, status=status.HTTP_400_BAD_REQUEST)
#
#         # if user:
#         #     otp_user = OTPUser.objects.filter(user=user).first()
#         #     if not otp_user:
#         #         otp_user = OTPUser.objects.create(user=user)
#         #
#         #     return Response(
#         #         {"user": user.email, "otp": otp_user.generate_otp, "key": otp_user.key},
#         #         status=status.HTTP_200_OK,
#         #     )
#         return Response({"user": "NOT FOUND"}, status=status.HTTP_404_NOT_FOUND)
#
#     def post(self, request):
#         user = User.objects.get_by_natural_key("tristar3")
#         if not user:
#             return Response({"user": "NOT FOUND"}, status=status.HTTP_404_NOT_FOUND)
#
#         serializer = OTPSerializer(data=request.data)
#         if serializer.is_valid():
#             otp_token = serializer.data["otp"]
#             otp_user = OTPUser.objects.filter(user=user).first()
#             if not otp_user:
#                 return Response(status=status.HTTP_403_FORBIDDEN)
#             is_otp_valid = otp_user.verify_otp(int(otp_token))
#             return Response(
#                 {
#                     "otp": otp_token,
#                     "user_otp": otp_user.generate_otp,
#                     "user_key": otp_user.key,
#                     "is_valid": is_otp_valid,
#                 },
#                 status=status.HTTP_200_OK,
#             )
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#
