import json
import logging
import time
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
from v2.serializers import FriendSerializer

logger = logging.getLogger(__name__)


@api_view(['POST'])
def register_device(request: Request) -> Response:
    """
    POST: Registers a device for receiving alerts for an account.

    Requires `fcm_token` parameter to be set to the Firebase Cloud Messaging token to use for that device

    Requires authentication.

    Returns status 400 if the token is already registered to the account
    Returns status 200 otherwise
    No data is returned.
    """
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
    """
    POST: Registers a new user account with the provided credentials

    Requires `first_name`, `last_name`, `username`, and `password`. Optionally accepts `email` as well. Username will be
    a unique identifier for the user. Email is currently not used, but may at some point be used for password reset/MFA/
    account alerts.

    Does not require authentication.

    If the username is already taken: returns status 400 with message "Username taken"
    Otherwise: status 200
    Returns no data.
    """
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
    """
    POST: Adds a user as a friend of the authenticated user. This allows the other user to send messages to the authenticated
    user, but not the other way around (unless that user adds this user as a friend).

    Requires the `username` parameter to be set.

    Requires authentication.

    Returns no data.
    """
    good, response = check_params(['username'], request.data)
    if not good:
        return response

    try:
        Friend.objects.update_or_create(owner_id=request.user.username, friend_id=request.data[
            'username'], defaults={'deleted': False})
        return Response(build_response(True, 'Successfully added/restored friend'), 200)
    except IntegrityError:
        return Response(build_response(False, 'An error occurred when restoring friend'), 400)


@api_view(['GET', 'HEAD'])
def get_friend_name(request: Request) -> Response:
    """
    GET: Gets the name corresponding to a particular username.

    Requires the `username` parameter.

    Requires authentication.

    Returns the following data:
    {
        first_name: <user's first name>,
        last_name: <user's last name>
    }
    """
    good, response = check_params(['username'], request.query_params)
    if not good:
        return response

    try:
        friend: User = User.objects.get(username=request.query_params['username'])
        return Response(build_response(True, 'Got name', {'first_name': friend.first_name, 'last_name':
            friend.last_name}), status=200)
    except User.DoesNotExist:
        return Response(build_response(False, "Couldn't find user"), status=400)


@api_view(['DELETE'])
def delete_friend(request: Request) -> Response:
    """
    DELETE: This friend relationship will be lazy-deleted, and can be fully undone by adding the friend back.

    Requires the `friend` parameter to be set to a current friend of the authenticated user.

    Requires authentication.

    Returns status 400 if the other user is not a friend, and no data.
    """
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
    """
    DELETE: Truly deletes all data associated with the authenticated user (not lazy deletion, cannot be
    undone). Includes references to the user other people have in their friend lists, etc.

    Accepts no parameters.

    Requires authentication.

    Returns no data.
    """
    User.objects.get(username=request.user.username).delete()
    return Response(build_response(True, 'Successfully deleted user data'), status=200)


@api_view(['PUT'])
def edit_user(request: Request) -> Response:
    """
    PUT: Updates the corresponding fields for the authenticated user.

    Has 3 optional parameters: `first_name`, `last_name`, and `password`.

    Requires authentication.

    Returns no data.
    """
    user = request.user
    if 'first_name' in request.data:
        user.first_name = request.data['first_name']
    if 'last_name' in request.data:
        user.last_name = request.data['last_name']
    if 'password' in request.data:
        user.set_password(request.data['password'])
    user.save()
    return Response(build_response(True, 'User updated successfully'), status=200)


@api_view(['GET', 'HEAD'])
def get_user_info(request: Request) -> Response:
    """
    GET: Returns a data dump based on the user used to authenticate.

    Accepts no parameters.

    Requires authentication.

    On success, returns the following in the data field:
    {
        first_name: <user's first name>,
        last_name: <user's last name>,
        friends: [
            {
                owner: <username>,
                friend: <friend's username>,
                sent: <number of messages sent to friend>,
                received: <number of messages received from friend>
            },
            ...
        ]
    }
    """
    user: User = request.user
    friends = [FriendSerializer(x) for x in Friend.objects.filter(owner_id=user.username)]
    data = {
        'first_name': user.first_name,
        'last_name': user.last_name,
        'friends': friends,
    }
    return Response(build_response(True, 'Got user data', data=data), status=200)


@api_view(['POST'])
def send_alert(request: Request) -> Response:
    """
    POST: Sends an alert with an optional message to a user. The user must have the authenticated user added as a friend
    for this to succeed.

    Requires `to` and `message` to be set as parameters. If `message` is 'null', the app should display the default "no
    message" alert.

    Requires authentication.

    Returns status 400 on error
    On success, returns the following data:
    {
        'id': <alert id>
    }
    """
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
    alert_id = time.time()
    for token in tokens:
        message = messaging.Message(
            data={
                'action': 'alert',
                'alert_id': alert_id,
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
    return Response(build_response(True, "Successfully sent message", data={'id': alert_id}), status=200)


@api_view(['POST'])
def alert_read(request: Request) -> Response:
    """
    POST: Sends a signal to dismiss an alert on all of the user's other devices.

    Requires `alert_id`, `from`, and `fcm_token` parameters to be set.

    Requires authentication.

    Returns no data.
    """
    good, response = check_params(['alert_id', 'from', 'fcm_token'], request.data)
    if not good:
        return response

    tokens: QuerySet = FCMTokens.objects.filter(username=request.data['from']).exclude(fcm_token=request.data[
        'fcm_token']).union(FCMTokens.objects.filter(username=request.user.username))

    if len(tokens) == 0:
        logger.warning("Could not find tokens for recipient or the users other devices")
        return Response(build_response(False, f'An error occurred'), status=500)
    try:
        firebase_admin.initialize_app()
    except ValueError:
        logger.info('Firebase Admin app already initialized')

    at_least_one_success: bool = False
    alert_id = time.time()
    for token in tokens:
        message = messaging.Message(
            data={
                'action': 'read',
                'alert_id': alert_id,
            },
            android=messaging.AndroidConfig(
                priority='low'
            ),
            token=token
        )

        try:
            response = messaging.send(message)
            at_least_one_success = True
        except InvalidArgumentError as e:
            logger.warning(f'An alert failed to send: {e.cause}')

    if not at_least_one_success:
        return Response(build_response(False, f"Unable to send read status"), status=400)
    return Response(build_response(True, "Successfully sent read status"), status=200)


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
