import os
import hashlib
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import User, File
from rest_framework import status
from .serializers import UserSerializer, FileSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.http import Http404
from django.core.mail import send_mail
from django.conf import settings
from core import utils as coreUtils
from django.http import FileResponse
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.views import APIView

class LoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        if not username or not password:
            return Response({"error": "Please provide both username and password."}, status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_verified:
                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                return Response(
                    {
                        "message": "Login successful!",
                        "access_token": str(refresh.access_token),
                        "refresh_token": str(refresh),
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response({"error": "Email is not verified."}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({"error": "Invalid username or password."}, status=status.HTTP_401_UNAUTHORIZED)


class SignupView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.verification_hash = hashlib.sha256(user.email.encode()).hexdigest()
            user.save()
            verification_url = f"https://tambolipradhuman123.pythonanywhere.com/api/verify-email/{user.verification_hash}"

            send_mail(
                'Email Verification',
                f'Please verify your email by clicking on this link: {verification_url}',
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            return Response(
                {
                    "message": "User created successfully!",
                    "verification_hash": user.verification_hash,
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    def get(self, request, encrypted_url):
        try:
            user = User.objects.get(verification_hash=encrypted_url)
            user.is_verified = True
            user.save()
            return Response({"message": "Email verified successfully!"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            raise Http404("User not found or invalid verification URL")


class UploadFileView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure that the user is authenticated
    authentication_classes = [JWTAuthentication]  # Use JWTAuthentication

    parser_classes = [MultiPartParser, FormParser]  # Add parsers

    def post(self, request):
        user = request.user

        if user.role != 'ops':
            return Response({"error": "Only Ops users can upload files."}, status=status.HTTP_403_FORBIDDEN)

        file = request.FILES.get('file')  # Get the uploaded file
        if not file:
            return Response({"error": "No file uploaded."}, status=status.HTTP_400_BAD_REQUEST)

        # Validate file type
        valid_extensions = ['.pptx', '.docx', '.xlsx']
        file_extension = os.path.splitext(file.name)[1].lower()
        if file_extension not in valid_extensions:
            return Response({"error": "Invalid file type. Only pptx, docx, and xlsx are allowed."}, status=status.HTTP_400_BAD_REQUEST)


        file_instance = File(file=file, uploaded_by=user)
        file_instance.save()

        return Response({"message": "File uploaded successfully"}, status=status.HTTP_201_CREATED)


class FileDownloadView(APIView):
    def get(self, request, file_id):

        if not request.user.is_authenticated or request.user.role != "client":
            return Response({"error": "Unauthorized access"}, status=status.HTTP_403_FORBIDDEN)

        try:
            File.objects.get(id=file_id)
        except File.DoesNotExist:
            return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)

        # Encrypt the URL (for secure access)
        encrypted_url = coreUtils.encrypt_file_url(file_id)


        return Response(
                {
                    "message": "Success",
                    "encrypted_url": encrypted_url
                },status=status.HTTP_200_OK)


class ListFilesView(APIView):
    def get(self, request):
        if not request.user.is_authenticated :
            return Response({"error": "Authentication Required", "message": "You must be logged in to access this resource.","details": "Include the token in the Authorization header in the format: 'Bearer <your_token>'."},
                            status=403)
        # Ensure only client users can access the file
        if request.user.role != 'client':
            return Response({"error": "Access Denied", "message": "This resource is only accessible to client users."},
                            status=403)

        # List all files uploaded by Ops users
        files = File.objects.all()
        serialized_files = FileSerializer(files, many=True)

        return Response(serialized_files.data, status=status.HTTP_200_OK)


class SecureFileDownloadView(APIView):
    def get(self, request, encrypted_url):
        try:
            # Decrypt the URL to get the file ID
            file_id = coreUtils.decrypt_file_url(encrypted_url)
            file_instance = File.objects.get(id=file_id)

            if not request.user.is_authenticated :
                return Response({"error": "Authentication Required", "message": "You must be logged in to access this resource.","details": "Include the token in the Authorization header in the format: 'Bearer <your_token>'."},
                                status=403)

            if request.user.role != 'client':
                return Response({"error": "Access Denied", "message": "This resource is only accessible to client users."},
                                status=403)

            # Serve the file
            response = FileResponse(file_instance.file)
            response['Content-Disposition'] = f'attachment; filename="{file_instance.file.name}"'
            return response
        except File.DoesNotExist:
            return Response({"error": "File not found"}, status=404)
        except ValueError:
            return Response({"error": "Invalid or corrupted URL"}, status=400)
