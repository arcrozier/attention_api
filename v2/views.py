import json
from typing import Any

from django.shortcuts import render

# Create your views here.
from rest_framework.views import APIView

from v2.models import Users


class ApiV2(APIView):
    queryset = Users.objects.all()


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
