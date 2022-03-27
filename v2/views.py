import json
import logging
from typing import Any, Tuple, Dict

import firebase_admin
from django.contrib.auth.models import User
from django.db import transaction, IntegrityError
from django.db.models import QuerySet
from firebase_admin import messaging
from firebase_admin.exceptions import InvalidArgumentError
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response

from v2.models import FCMTokens, Friend

logger = logging.getLogger(__name__)


@api_view(['POST'])
def register_device(request: Request) -> Response:
    good, response = check_params(['fcm_token'], request.data)
    if not good:
        return response

    try:
        FCMTokens.objects.create(username=request.user.username, fcm_token=request.data['fcm_token'])
    except IntegrityError:
        return Response(build_response(False, 'That token is already registered'), status=400)
    return Response(build_response(True, 'Token successfully registered'), status=200)


@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request: Request) -> Response:
    good, response = check_params(['first_name', 'last_name', 'username', 'password'], request.data)
    if not good:
        return response

    try:
        User.objects.create_user(first_name=request.data['first_name'], last_name=request.data['last_name'],
                                 username=request.data['username'], password=request.data['password'],
                                 email=request.data.get('email'))
    except IntegrityError:
        return Response(build_response(False, 'Username taken'), status=400)
    return Response(build_response(True, 'User created'), status=200)


@api_view(['POST'])
def add_friend(request: Request) -> Response:
    good, response = check_params(['username'], request.data)
    if not good:
        return response

    try:
        Friend.objects.update_or_create(owner_id=request.user.username, friend_id=request.data[
            'username'], defaults={'deleted': False})
        return Response(build_response(True, 'Successfully added/restored friend'), 200)
    except IntegrityError:
        return Response(build_response(False, 'An error occurred when restoring friend'), 400)


@api_view(['GET'])
def get_friend_name(request: Request) -> Response:
    good, response = check_params(['username'], request.data)
    if not good:
        return response

    try:
        friend: User = User.objects.get(username=request.data['username'])
        return Response(build_response(True, 'Got name', {'first_name': friend.first_name, 'last_name':
            friend.last_name}), status=200)
    except User.DoesNotExist:
        return Response(build_response(False, "Couldn't find user"), status=400)


@api_view(['DELETE'])
def delete_friend(request: Request) -> Response:
    good, response = check_params(['friend'], request.data)
    if not good:
        return response

    try:
        friend = Friend.objects.get(owner_id=request.user.username, friend_id=request.data['friend'])
        friend.deleted = True
        friend.save()
        return Response(build_response(True, 'Successfully deleted friend'), status=200)
    except Friend.DoesNotExist:
        return Response(build_response(False, 'Could not delete friend as you were not friends'), status=400)


@api_view(['DELETE'])
def delete_user_data(request: Request) -> Response:
    User.objects.get(username=request.user.username).delete()
    return Response(build_response(True, 'Successfully deleted user data'), status=200)


@api_view(['PUT'])
def edit_user(request: Request) -> Response:
    user = User.objects.get(username=request.user.username)
    if request
    pass
    # This can take first name, last name, and/or password as parameters - if password is provided, delete the token
    # and update the password


@api_view(['GET'])
def get_user_info(request: Request) -> Response:
    pass


# This should return all the user data (except username/password): first name, last name, all friends, all messages (
# when implemented)


@api_view(['POST'])
def send_alert(request: Request) -> Response:
    # unauthenticated requests should be denied automatically - test this
    good, response = check_params(['to', 'message'], request.data)
    if not good:
        return response

    to: str = request.data['to']

    try:
        Friend.objects.get(owner__username=to, friend__username=request.user.username, deleted=False)
    except Friend.DoesNotExist:
        return Response(build_response(False, f'Could not send message as {to} does not have you as a friend'),
                        status=403)

    tokens: QuerySet = FCMTokens.objects.filter(username=to)
    if len(tokens) == 0:
        return Response(build_response(False, f'Could not find user {to}'), status=400)
    try:
        firebase_admin.initialize_app()
    except ValueError:
        logger.info('Firebase Admin app already initialized')

    at_least_one_success: bool = False
    for token in tokens:
        message = messaging.Message(
            data={
                'alert_to': request.data['to'],
                'alert_from': request.user.username,
                'alert_message': request.data['message']
            },
            android=messaging.AndroidConfig(
                priority='high'
            ),
            token=token
        )

        try:
            response = messaging.send(message)
            at_least_one_success = True
        except InvalidArgumentError as e:
            logger.warning(f'An alert failed to send: {e.cause}')

    if not at_least_one_success:
        return Response(build_response(False, f"Unable to send message"), status=400)
    return Response(build_response(True, "Successfully sent message"), status=200)


def check_params(expected: list, holder: Dict) -> Tuple[bool, Response]:
    missing: list = []
    for expect in expected:
        if expect not in holder:
            missing.append(expect)
    response = Response(build_response(False, f"Missing required parameter(s): {', '.join(missing)}"),
                        status=400) if len(missing) != 0 else Response()
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
