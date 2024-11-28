from django.urls import path
from core import views as coreView


urlpatterns = [
    path('login/', coreView.LoginView.as_view(), name='login'),
    path('signup/', coreView.SignupView.as_view(), name='signup'),
    path('upload/', coreView.UploadFileView.as_view(), name='file-upload'),
    path('verify-email/<str:encrypted_url>/', coreView.VerifyEmailView.as_view(), name='verify-email'),
    path('download/<int:file_id>/', coreView.FileDownloadView.as_view(), name='file-download'),
    path('list-files/', coreView.ListFilesView.as_view(), name='list-files'),
    path('secure-download/<str:encrypted_url>/', coreView.SecureFileDownloadView.as_view(), name='secure-file-download'),
]




