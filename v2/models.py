from typing import Final

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _


# Create your models here.
class User(AbstractUser):
    email = models.EmailField(_('email'), blank=True, null=True, unique=True)
    google_id = models.CharField(max_length=100, unique=True, blank=True, null=True)

    def save(self, *args, **kwargs):
        if self.email is not None and self.email.strip() == "":
            self.email = None
        if self.google_id == "":
            self.google_id = None
        super().save(*args, **kwargs)


class Photo(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    photo = models.TextField()

    PHOTO_SIZE: Final = 128


class Friend(models.Model):
    READ = 'r'
    DELIVERED = 'd'
    SENT = 's'
    DELIVERY_CHOICES = [
        (READ, 'Read'),
        (DELIVERED, "Delivered"),
        (SENT, "Sent"),
    ]
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='friend_set')
    friend = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='friend_of_set')
    name = models.CharField(max_length=150, null=True)
    sent = models.IntegerField(default=0)
    received = models.IntegerField(default=0)
    deleted = models.BooleanField(default=False)
    blocked = models.BooleanField(default=False)
    last_sent_message_status = models.CharField(max_length=1, choices=DELIVERY_CHOICES, null=True, default=None)
    last_sent_alert_id = models.CharField(max_length=100, null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['owner', 'friend'], name='unique_relationships')
        ]

    def __str__(self):
        return f"{self.owner} {'!' if self.blocked else 'x' if self.deleted else ''}-> {self.friend}"


class FCMTokens(models.Model):
    user = models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    fcm_token = models.TextField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'fcm_token'], name='no_duplicate_user_tokens')
        ]
