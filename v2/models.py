from django.db import models

# Create your models here.


class Users(models.Model):
    public_key = models.CharField(max_length=255, primary_key=True)
    fcm_id = models.TextField(unique=True)
    challenge = models.CharField(max_length=16)
    challenge_timeout = models.DateTimeField()

