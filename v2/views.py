import base64
import json
from typing import Any, Tuple, Dict

import firebase_admin
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.db import transaction
from firebase_admin import messaging
from firebase_admin.exceptions import InvalidArgumentError
from rest_framework.decorators import api_view
from rest_framework.request import Request
from rest_framework.response import Response

from v2.models import Challenge
from v2.models import User


@api_view(['GET'])
def get_challenge(request: Request, public_key: str) -> Response:
    try:
        user = User.objects.get(public_key=public_key)
        challenge = Challenge(id=user)
        challenge.save()
        return Response(build_response(True, "Successfully generated challenge", data=str(challenge.challenge)),
                        status=200)
    except User.DoesNotExist:
        return Response(build_response(False, "An error occurred retrieving a challenge"), status=403)


@api_view(['POST', 'PUT'])
def upload_public_key(request: Request) -> Response:
    good, response = check_params(['id', 'token'], request.data)
    if not good:
        return response

    try:
        with transaction.atomic():
            user, created = User.objects.update_or_create(public_key=request.data['id'], defaults={
                'fcm_id': request.data['token']})
            if not created:
                # An existing user is being updated - we need the caller to authenticate
                verify_challenge(request.data['challenge'], request.data['id'], request.data['signature'])
    except KeyError:
        return Response(build_response(False, 'To update a user, a signed challenge must be provided'), status=403)
    except InvalidSignature or Challenge.DoesNotExist:
        return Response(build_response(False, 'The provided challenge was invalid or not signed correctly'), status=403)

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

    try:
        verify_challenge(request.data['challenge'], request.data['from'], request.data['signature'])
    except (Challenge.DoesNotExist, ValueError):
        return Response(build_response(False, "Challenge was not recognized"), status=403)
    except InvalidSignature:
        return Response(build_response(False, "Challenge verification failed"), status=403)

    token: str
    try:
        token = User.objects.get(public_key=request.data['from']).fcm_id
    except User.DoesNotExist:
        return Response(build_response(False, "User not found"), status=403)
    try:
        firebase_admin.initialize_app()
    except ValueError:
        print('app already initialized')

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

    try:
        response = messaging.send(message)
    except InvalidArgumentError as e:
        return Response(build_response(False, f"An error occurred when sending message: {e.cause}"), status=400)

    return Response(build_response(True, "Successfully sent message"), status=200)


def verify_challenge(challenge_str: str, user: str, signature: str):
    """
    Verifies and consumes a challenge
    :param challenge_str: The challenge the client signed
    :param user: The client's user id (public key - base64 DER encoding)
    :param signature: The signature the client provided to verify

    :raises InvalidSignature: If the signature was not correctly signed
    :raises Challenge.DoesNotExist: If the challenge is not valid
    """
    with transaction.atomic():
        # Lookup the valid challenge associated with the user - if a matching challenge doesn't exist, raises
        # Challenge.DoesNotExist - establishes a lock on the row until the transaction completes
        challenge = Challenge.objects.select_for_update().get(challenge=challenge_str,
                                                              id_id=user, valid=True)
        # Verify that the challenge was signed by that id
        verify_signature(str(challenge.challenge), signature, challenge.id.public_key)

        # Challenge is no longer valid
        challenge.valid = False
        challenge.save()


def verify_signature(challenge: str, signature: str, public_key: str) -> None:
    """
    Verifies whether the challenge was signed by the provided public_key
    :param challenge: The unsigned version that the user signed
    :param signature: The signature that the user signed with their private key
    :param public_key: The public key associated with the private key used to sign

    :throws InvalidSignature: If the challenge was improperly signed
    """
    loaded_key = serialization.load_der_public_key(base64.urlsafe_b64decode(public_key))
    loaded_key.verify(base64.urlsafe_b64decode(signature), challenge.encode(), ec.ECDSA(hashes.SHA256()))


def check_params(expected: list, holder: Dict) -> Tuple[bool, Response]:
    missing: list = []
    for expect in expected:
        if expect not in holder:
            missing.append(expect)
    response = Response(build_response(False, f"Missing required parameter(s): {', '.join(missing)}", string=True),
                        status=400) if len(missing) != 0 else Response()
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
