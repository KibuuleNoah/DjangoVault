from django.urls import reverse
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.test import APIClient, APITestCase
from Auth.models import OTPUser
from unittest.mock import patch


class SignUpViewTests(APITestCase):

    def setUp(self):
        self.client = APIClient()
        self.signup_url = reverse("signup")  # Assuming the signup URL name is 'signup'
        self.valid_user_data = {
            "username": "testuser",
            "email": "testuser@example.com",
            "password1": "TestPassword123",
            "password2": "TestPassword123",
        }
        self.invalid_user_data = {
            "username": "testuser",
            "email": "testuser@example.com",
            "password1": "TestPassword123",
            "password2": "TestPassword",
        }

    @patch("Auth.views.send_otp_email")  # Mock the send_otp_email function
    def test_signup_success(self, mock_send_otp_email):
        # Ensure no user with the test email exists
        self.assertFalse(
            User.objects.filter(email=self.valid_user_data["email"]).exists()
        )

        # Simulate sending OTP
        mock_send_otp_email.return_value = None

        response = self.client.post(
            self.signup_url, self.valid_user_data, format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["username"], self.valid_user_data["username"])
        self.assertEqual(response.data["email"], self.valid_user_data["email"])
        self.assertTrue(
            User.objects.filter(email=self.valid_user_data["email"]).exists()
        )
        self.assertTrue(
            OTPUser.objects.filter(user__email=self.valid_user_data["email"]).exists()
        )

        # Check that OTP is returned in the response for development purposes
        otp_user = OTPUser.objects.get(user__email=self.valid_user_data["email"])
        self.assertIn("otp", response.data)
        self.assertEqual(response.data["otp"], otp_user.otp)

    def test_signup_failure(self):
        response = self.client.post(
            self.signup_url, self.invalid_user_data, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password2", response.data)
        self.assertFalse(
            User.objects.filter(email=self.invalid_user_data["email"]).exists()
        )
