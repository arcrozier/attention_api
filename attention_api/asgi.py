"""
ASGI config for attention_api project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/howto/deployment/asgi/
"""

import os
from dotenv import load_dotenv

from django.core.asgi import get_asgi_application

import logging

load_dotenv()
load_dotenv(os.environ["DB_CREDENTIALS_FILE"])
if (os.environ.get("SERVICE_ACCOUNT_FILE")):
    load_dotenv(os.environ["SERVICE_ACCOUNT_FILE"])

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "attention_api.settings")

logger = logging.getLogger(__name__)
logger.info(f"Settings module: {os.environ['DJANGO_SETTINGS_MODULE']}")

application = get_asgi_application()
