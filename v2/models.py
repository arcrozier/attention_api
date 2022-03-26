from django.contrib.auth.models import User
from django.db import models


# Create your models here.
class Friend(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    friend = models.ForeignKey(User, on_delete=models.CASCADE)
    sent = models.IntegerField(default=0)
    received = models.IntegerField(default=0)
    deleted = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['owner', 'friend'], name='unique_relationships')
        ]


class FCMTokens(models.Model):
    username = models.ForeignKey(to=User, on_delete=models.CASCADE)
    fcm_token = models.TextField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['username', 'fcm_token'], name='no_duplicate_user_tokens')
        ]
