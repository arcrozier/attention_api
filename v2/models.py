from django.db import models

# Create your models here.
from django.db.models import CASCADE


class User(models.Model):
    public_key = models.CharField(max_length=255, primary_key=True)
    fcm_id = models.TextField(unique=True)


class Challenge(models.Model):
    challenge = models.BigAutoField(primary_key=True)
    id = models.ForeignKey(to=User, on_delete=CASCADE)
