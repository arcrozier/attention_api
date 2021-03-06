from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.validators import ASCIIUsernameValidator
from django.db import models


# Create your models here.
class User(AbstractUser):
    username = models.CharField(max_length=150, unique=True, blank=False, validators=[ASCIIUsernameValidator()])
    email = models.EmailField(unique=True, blank=True, null=True, default=None, verbose_name='email address')

    def save(self, *args, **kwargs):
        if self.email == "":
            self.email = None
        super().save(*args, **kwargs)


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
    last_sent_message_status = models.CharField(max_length=1, choices=DELIVERY_CHOICES, null=True, default=None)
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
