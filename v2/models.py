from django.contrib.auth.models import User
from django.db import models


# Create your models here.
class Friend(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='friend_set')
    friend = models.ForeignKey(User, on_delete=models.CASCADE, related_name='friend_of_set')
    sent = models.IntegerField(default=0)
    received = models.IntegerField(default=0)
    deleted = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['owner', 'friend'], name='unique_relationships')
        ]


class FCMTokens(models.Model):
    user = models.ForeignKey(to=User, on_delete=models.CASCADE)
    fcm_token = models.TextField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'fcm_token'], name='no_duplicate_user_tokens')
        ]
