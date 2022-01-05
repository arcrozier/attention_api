import json
from base64 import b64decode
from hashlib import sha256
from typing import Any, Tuple

from django.http import QueryDict
from ecdsa import BadSignatureError

from rest_framework.decorators import api_view
from rest_framework.request import Request
from rest_framework.response import Response

import ecdsa

from v2.models import User
from v2.models import Challenge


@api_view(['GET'])
def get_challenge(request: Request, public_key: str) -> Response:
    try:
        user = User.objects.get(public_key=public_key)
        challenge = Challenge(id=user)
        challenge.save()
        return Response(build_response(True, "Successfully generated challenge", data=str(challenge), string=True),
                        status=200)
    except User.DoesNotExist:
        return Response(build_response(False, "An error occurred retrieving a challenge", string=True), status=403)


@api_view(['POST', 'PUT'])
def upload_public_key(request: Request) -> Response:
    good, response = check_params(['id', 'token'], request.data)
    if not good:
        return response
    user, created = User.objects.update_or_create(public_key=request.data['id'], fcm_id=request.data['token'])
    message: str
    if created:
        message = "Successfully created new user"
    else:
        message = "Successfully updated user"
    return Response(build_response(True, message, string=True), status=200)


@api_view(['POST'])
def send_alert(request: Request) -> Response:
    good, response = check_params(['to', 'from', 'message', 'signature'], request.data)
    if not good:
        return response
    pass


def verify_signature(challenge: str, signed: str, public_key: str) -> bool:
    verifying_key = ecdsa.VerifyingKey.from_string(b64decode(public_key), curve=ecdsa.SECP256k1, hashfunc=sha256)
    try:
        verifying_key.verify(b64decode(signed), challenge)
        return True
    except BadSignatureError:
        return False


def check_params(expected: list, holder: QueryDict) -> Tuple[bool, Response]:
    missing: list = []
    for expect in expected:
        if expect not in holder:
            missing.append(expect)
    response = Response(build_response(False, f"Missing required parameter(s): {', '.join(missing)}", string=True),
                        status=400)
    return len(missing) == 0, response


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
