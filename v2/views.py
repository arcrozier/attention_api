import json
from base64 import b64decode
from hashlib import sha256
from typing import Any, Tuple

import firebase_admin
from django.db import transaction
from django.http import QueryDict
from ecdsa import BadSignatureError
from firebase_admin import messaging

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
        return Response(build_response(True, "Successfully generated challenge", data=str(challenge)),
                        status=200)
    except User.DoesNotExist:
        return Response(build_response(False, "An error occurred retrieving a challenge"), status=403)


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
    return Response(build_response(True, message), status=200)


@api_view(['POST'])
def send_alert(request: Request) -> Response:
    good, response = check_params(['to', 'from', 'message', 'signature', 'challenge'], request.data)
    if not good:
        return response

    challenge: Challenge
    try:
        with transaction.atomic(using=Challenge):
            # Lookup the valid challenge associated with the user - if a matching challenge doesn't exist, raises
            # Challenge.DoesNotExist - establishes a lock on the row until the transaction completes
            challenge = Challenge.objects.select_for_update().get(challenge=request.data['challenge'],
                                                                  id_id=request.data['from'], valid=True)
            # Verify that the challenge was signed by that id
            if not verify_signature(str(challenge.challenge), request.data['signature'], challenge.id.public_key):
                return Response(build_response(False, "Challenge verification failed"), status=403)

            # Challenge is no longer valid
            challenge.valid = False
            challenge.save()
    except Challenge.DoesNotExist:
        return Response(build_response(False, "Challenge was not recognized"), status=403)

    token: str
    try:
        token = User.objects.get(public_key=request.data['from']).fcm_id
    except User.DoesNotExist:
        return Response(build_response(False, "User not found"), status=403)
    firebase_app = firebase_admin.initialize_app()

    message = messaging.Message(
        data={
            'alert_to': request.data['to'],
            'alert_from': request.data['from'],
            'alert_message': request.data['message']
        },
        android=messaging.AndroidConfig(
            priority='high'
        ),
        token=token
    )
    response = messaging.send(message)

    return Response(build_response(True, "Successfully sent message"), status=200)


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


def build_response(success: bool, message: str, data: Any = None, string: bool = True) -> dict:
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
