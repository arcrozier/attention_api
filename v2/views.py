import json
from typing import Any

from django.shortcuts import render

# Create your views here.
from rest_framework.decorators import api_view
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from v2.models import User
from v2.models import Challenge


@api_view(['GET'])
def get_challenge(request: Request, public_key: str) -> Response:
    # TODO: Generate a new challenge
    try:
        user = User.objects.get(public_key=public_key)
        challenge = Challenge(id=user.public_key)
    except User.DoesNotExist:
        return Response(build_response(False, "An error occurred retrieving a challenge", 403, True))


@api_view(['POST'])
def upload_public_key(request: Request) -> Response:
    pass


@api_view(['POST'])
def send_alert(request: Request) -> Response:
    pass


def build_response(success: bool, message: str, data: Any = None, string: bool = False) -> dict:
    response = {
        "success": success,
        "message": message,
        "data": data
    }
    if string:
        response = string_response(response)
    return response


def string_response(args: dict):
    return json.dumps(args)
