import firebase_admin
from django.apps import AppConfig


class V2Config(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'v2'

    def ready(self):
        firebase_admin.initialize_app()
