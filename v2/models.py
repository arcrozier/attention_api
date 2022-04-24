from django.conf import settings
from django.contrib.auth.models import AbstractUser, User
from django.contrib.auth.validators import ASCIIUsernameValidator
from django.db import models


# Create your models here.
class Friend(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='friend_set')
    friend = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='friend_of_set')
    name = models.CharField(max_length=150, null=True)
    sent = models.IntegerField(default=0)
    received = models.IntegerField(default=0)
    deleted = models.BooleanField(default=False)
    last_sent_message_read = models.BooleanField(default=False)
    last_sent_alert_id = models.CharField(max_length=100, null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['owner', 'friend'], name='unique_relationships')
        ]


class FCMTokens(models.Model):
    user = models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    fcm_token = models.TextField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'fcm_token'], name='no_duplicate_user_tokens')
        ]
