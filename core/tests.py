from django.test import TestCase
# Create your tests here.
from rest_framework.test import APITestCase
from rest_framework import status
from django.core import mail
from .models import User
from django.urls import reverse
from .models import File
from core import utils as coreUtils

class SignupViewTest(APITestCase):
    def test_signup(self):
        url = reverse('signup')  # Ensure to add the correct URL pattern name
        data = {
            "username": "johndoe",
            "email": "johndoe@example.com",
            "password": "securepassword",
            "password2": "securepassword",
            "role": "ops",
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("verification_hash", response.data)

        # Check that an email has been sent
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('Email Verification', mail.outbox[0].subject)

class LoginViewTest(APITestCase):
    def setUp(self):
        # Create a user
        self.user = User.objects.create_user(
            username="johndoe", email="johndoe@example.com", password="securepassword", role="client", is_verified=True
        )
        
    def test_login_success(self):
        url = reverse('login')  # Ensure to add the correct URL pattern name
        data = {
            "username": "johndoe",
            "password": "securepassword",
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)

    def test_login_invalid_credentials(self):
        url = reverse('login')  # Ensure to add the correct URL pattern name
        data = {
            "username": "johndoe",
            "password": "wrongpassword",
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)

class VerifyEmailViewTest(APITestCase):
    def setUp(self):
        # Create a user
        self.user = User.objects.create_user(
            username="johndoe", email="johndoe@example.com", password="securepassword", role="client"
        )
        self.user.verification_hash = "testhash"
        self.user.save()

    def test_verify_email_success(self):
        url = reverse('verify-email', kwargs={'encrypted_url': 'testhash'})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_verified)

    def test_verify_email_invalid_hash(self):
        url = reverse('verify-email', kwargs={'encrypted_url': 'invalidhash'})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model

User = get_user_model()
import tempfile

class UploadFileViewTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="johndoe", email="johndoe@example.com", password="securepassword", role="ops", is_verified=True
        )
        # Create a JWT token for the user
        refresh = RefreshToken.for_user(self.user)
        self.token = str(refresh.access_token)  # Store the access token as a string

    def test_upload_file_success(self):
        url = reverse('file-upload')
        with open('testfile.pptx', 'wb') as f:
            f.write(b'This is a test file.')

        with open('testfile.pptx', 'rb') as f:
            # Use the correct JWT token in the Authorization header
            response = self.client.post(
                url, {'file': f}, HTTP_AUTHORIZATION=f'Bearer {self.token}', format='multipart'
            )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_upload_file_invalid_role(self):
        self.user.role = 'client'  # Changing the role to 'client'
        self.user.save()
        url = reverse('file-upload')
        with open('testfile.pptx', 'wb') as f:
            f.write(b'This is a test file.')

        with open('testfile.pptx', 'rb') as f:
            # Use the correct JWT token in the Authorization header
            response = self.client.post(
                url, {'file': f}, HTTP_AUTHORIZATION=f'Bearer {self.token}', format='multipart'
            )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


# ------------


# class FileDownloadViewTest(APITestCase):
#     def setUp(self):
#         # Create a user and get their token
#         self.user = User.objects.create_user(
#             username="johndoe", email="johndoe@example.com", password="securepassword", role="client", is_verified=True
#         )
        
#         # Get JWT token for authentication
#         refresh = RefreshToken.for_user(self.user)
#         self.token = str(refresh.access_token)  # Store access token as a string
        
#         # Create a temporary file for testing
#         temp_file = tempfile.NamedTemporaryFile(delete=False)
#         temp_file.write(b'This is a test file.')
#         temp_file.close()  # Close the temp file to use it

#         # Create a file instance and save the temporary file to it
#         self.file = File.objects.create(file=temp_file.name, uploaded_by=self.user)

#     def test_download_file_success(self):
#         url = reverse('file-download', kwargs={'file_id': self.file.id})
        
#         # Make GET request with token authentication
#         response = self.client.get(url, HTTP_AUTHORIZATION=f'Bearer {self.token}')
        
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         self.assertIn('Content-Disposition', response.headers)
#         self.assertIn('attachment', response.headers['Content-Disposition'])  # To ensure the file is being downloaded

#     def test_download_file_not_found(self):
#         url = reverse('file-download', kwargs={'file_id': 9999})  # Non-existing file ID
        
#         # Make GET request with token authentication
#         response = self.client.get(url, HTTP_AUTHORIZATION=f'Bearer {self.token}')
        
#         self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

#     def test_download_unauthorized(self):
#         # Log out and try to download without authentication
#         self.client.logout()
#         url = reverse('file-download', kwargs={'file_id': self.file.id})
        
#         # Make GET request without authentication
#         response = self.client.get(url)
        
#         self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

# class ListFilesViewTest(APITestCase):
#     def setUp(self):
#         self.user = User.objects.create_user(
#             username="johndoe", email="johndoe@example.com", password="securepassword", role="client", is_verified=True
#         )
#         self.client.login(username='johndoe', password='securepassword')
#         self.file = File.objects.create(file='path_to_file', uploaded_by=self.user)

#     def test_list_files_success(self):
#         url = reverse('list-files')
#         response = self.client.get(url)
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         self.assertIn('files', response.data)

#     def test_list_files_not_authenticated(self):
#         self.client.logout()
#         url = reverse('list-files')
#         response = self.client.get(url)
#         self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

# class SecureFileDownloadViewTest(APITestCase):
#     def setUp(self):
#         self.user = User.objects.create_user(
#             username="johndoe", email="johndoe@example.com", password="securepassword", role="client", is_verified=True
#         )
#         self.client.login(username='johndoe', password='securepassword')
#         self.file = File.objects.create(file='path_to_file', uploaded_by=self.user)
#         self.encrypted_url = coreUtils.encrypt_file_url(self.file.id)  # Make sure to encrypt it

#     def test_secure_download_success(self):
#         url = reverse('secure-file-download', kwargs={'encrypted_url': self.encrypted_url})
#         response = self.client.get(url)
#         self.assertEqual(response.status_code, status.HTTP_200_OK)

#     def test_secure_download_invalid_url(self):
#         url = reverse('secure-file-download', kwargs={'encrypted_url': 'invalidurl'})
#         response = self.client.get(url)
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
