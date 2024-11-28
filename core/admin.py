from django.contrib import admin

# Register your models here.

from .models import User, File

@admin.register(User)
class userAdmin(admin.ModelAdmin):
        list_display = ['id', 'username', 'email', 'password', 'role', 'is_verified']


@admin.register(File)
class FileAdmin(admin.ModelAdmin):
        list_display = ['id', 'file', 'upload_at', 'uploaded_by']
