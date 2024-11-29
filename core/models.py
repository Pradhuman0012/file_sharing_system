from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    ROLE_CHOICES = [
        ('ops', 'Ops User'),
        ('client', 'Client User'),
    ]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    is_verified = models.BooleanField(default=False)
    verification_hash = models.CharField(max_length=64, blank=True, null=True)
    email = models.EmailField(unique=True)
    # Add related_name to avoid conflict
    groups = models.ManyToManyField(
        'auth.Group', related_name='core_user_set', blank=True)
    user_permissions = models.ManyToManyField(
        'auth.Permission', related_name='core_user_permissions_set', blank=True)

class File(models.Model):
    file = models.FileField(upload_to='uploads/', null=True, blank=True)  # File upload path
    upload_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='uploaded_files'
    )