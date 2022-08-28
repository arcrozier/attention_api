import base64
import io
import json
import logging
import time
from typing import Any, Tuple, Dict

import firebase_admin
from PIL.Image import DecompressionBombError
from django.conf import settings
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.validators import ASCIIUsernameValidator
from django.core.exceptions import ValidationError, PermissionDenied
from django.core.validators import validate_email
from django.db import transaction, IntegrityError
from django.db.models import QuerySet
from firebase_admin import messaging
from firebase_admin.exceptions import InvalidArgumentError
from firebase_admin.messaging import UnregisteredError
from google.auth.transport import requests
from google.oauth2 import id_token
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from PIL import Image, UnidentifiedImageError
from rest_framework.throttling import UserRateThrottle

from v2.models import FCMTokens, Friend, Photo

logger = logging.getLogger(__name__)

CLIENT_ID = '357995852275-tcfjuvtbrk3c57t5gsuc9a9jdfdn137s.apps.googleusercontent.com'


@api_view(['POST'])
def register_device(request: Request) -> Response:
    """
    /v2/register_device/
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
        with transaction.atomic():
            FCMTokens.objects.create(user=request.user, fcm_token=request.data['fcm_token'])
    except IntegrityError:
        return Response(build_response('That token is already registered'), status=400)
    return Response(build_response('Token successfully registered'), status=200)


@api_view(['POST'])
def unregister_device(request: Request) -> Response:
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
        with transaction.atomic():
            FCMTokens.objects.get(user=request.user, fcm_token=request.data['fcm_token']).delete()
    except FCMTokens.DoesNotExist:
        return Response(build_response('That token is not registered'), status=400)
    return Response(build_response('Token successfully unregistered'), status=200)


@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request: Request) -> Response:
    """
    /v2/register_user/
    POST: Registers a new user account with the provided credentials

    Requires `first_name`, `last_name`, `username`, `password`, and `tos_agree`. Optionally accepts `email` as well.
    Username will be a unique identifier for the user. Email is currently not used, but may at some point be used for
    password reset/MFA/account alerts.
    `tos_agree` must be "yes" (case-sensitive)

    This endpoint cannot be called more than 50 times per day per IP - exceeding this limit will result in status 429

    Does not require authentication.

    If the username is already taken: returns status 400 with message "Username taken"
    Otherwise: status 200
    Returns no data.
    """
    good, response = check_params(['first_name', 'last_name', 'username', 'password', 'tos_agree'], request.data)
    if not good:
        return response
    if request.data['tos_agree'] != 'yes':
        return Response(build_response('You must agree to the terms of service to register an account'),
                        status=400)
    if len(request.data['password']) < 8:
        return Response(build_response('Password must be at least 8 characters'), status=400)
    try:
        if 'email' in request.data and request.data['email'] != '':
            validate_email(request.data.get('email'))
        with transaction.atomic():
            ASCIIUsernameValidator()(request.data['username'])
            get_user_model().objects.create_user(first_name=request.data['first_name'],
                                                 last_name=request.data['last_name'],
                                                 username=request.data['username'],
                                                 password=request.data['password'],
                                                 email=request.data.get('email'))
    except IntegrityError:
        return Response(build_response('Username taken'), status=400)
    except ValidationError as e:
        return Response(build_response(e.message), status=400)
    return Response(build_response('User created'), status=200)


@api_view(['POST'])
@permission_classes([AllowAny])
def google_oauth(request: Request) -> Response:
    """
    /v2/google_auth/
    POST: Logs in the user with the provided Google user id token

    Requires `user_id` - a Google userid
    If creating an account, requires `username` parameter

    This endpoint cannot be called more than 50 times per day per IP - exceeding this limit will result in status 429

    Does not require authentication

    On success, returns the same as the api_token_auth endpoint - {'token': <token>}
    If the user wants to create an account, returns status 401 - should try again with the username parameter set
    If the Google account token is invalid, returns status 403
    """
    good, response = check_params(['id_token'], request.data)
    if not good:
        return response

    token = request.data['id_token']
    try:
        # Specify the CLIENT_ID of the app that accesses the backend:
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)

        # ID token is valid. Get the user's Google Account ID from the decoded token.
        userid = idinfo['sub']
        email = idinfo['email']
        first_name = idinfo['given_name']
        last_name = idinfo['family_name']
        user_set = get_user_model().objects.select_for_update().filter(google_id=userid)
        try:
            with transaction.atomic():
                if 'username' in request.data:
                    ASCIIUsernameValidator()(request.data['username'])
                    user = get_user_model().objects.create_user(first_name=first_name,
                                                                last_name=last_name,
                                                                username=request.data['username'],
                                                                email=email,
                                                                password=None)
                    user.google_id = userid
                    user.save()
                if user_set or 'username' in request.data:
                    token, _ = Token.objects.get_or_create(user=user_set.get())
                    return Response({'token': token})
                else:
                    return Response(build_response(message='Provide a username to create an account'),
                                    status=401)

        except IntegrityError:
            return Response(build_response('Username taken'), status=400)
        except ValidationError as e:
            return Response(build_response(e.message), status=400)

    except ValueError:
        # Invalid token
        return Response(build_response('Invalid Google token provided'), status=403)


@api_view(['POST'])
def add_friend(request: Request) -> Response:
    """
    /v2/add_friend/
    POST: Adds a user as a friend of the authenticated user. This allows the other user to send messages to the
    authenticated user, but not the other way around (unless that user adds this user as a friend).

    Requires the `username` parameter to be set.

    Requires authentication.

    Returns no data.
    """
    good, response = check_params(['username'], request.data)
    if not good:
        return response

    try:
        friend = get_user_model().objects.get(username=request.data['username'])
        Friend.objects.update_or_create(owner=request.user, friend=friend, defaults={
            'deleted': False})
        return Response(build_response('Successfully added/restored friend'), status=200)
    except IntegrityError:
        return Response(build_response('An error occurred when restoring friend'), status=400)
    except get_user_model().DoesNotExist:
        return Response(build_response('User does not exist'), status=400)


@api_view(['PUT'])
def edit_friend_name(request: Request) -> Response:
    """
    /v2/edit_friend_name/
    PUT: Edits the name this user has associated with their friend

    Every user can give each of their friends a custom name - only the user can see this, not the friend or anyone
    else (think of this like giving your friend a contact name). Thus, the relationship between users can be
    represented as a directed graph, with each user as a vertex, and friend relationships as edges between the
    vertices. The label of each edge is the friend name, only visible to the parent of the edge.

    user1 --[user1's name for user2]--> user2
    user2 --[user2's name for user1]--> user1
    There doesn't necessarily need to be a symmetric relationship between users: user1 ---> user2 but no edge from
    user2 to user1

    Requires `username` - this is the username of the friend - and `new_name` - this is the name to give them.

    If `username` is not a friend of the authenticated user, a friend relationship is created to store the
    information but it is marked as deleted.

    Requires authentication

    Returns no data
    """
    good, response = check_params(['username', 'new_name'], request.data)
    if not good:
        return response

    try:
        friend = get_user_model().objects.get(username=request.data['username'])
        rel, created = Friend.objects.update_or_create(owner=request.user, friend=friend,
                                                       defaults={'name': request.data['new_name']})
        if created:
            rel.deleted = True
            rel.save()
        return Response(build_response('Successfully updated friend name'), status=200)
    except IntegrityError:
        return Response(build_response('An error occurred when changing friend\'s name'), status=400)
    except get_user_model().DoesNotExist:
        return Response(build_response('An error occurred when restoring friend'), status=400)


@api_view(['GET', 'HEAD'])
def get_friend_name(request: Request) -> Response:
    """
    /v2/get_name/
    GET: Gets the name corresponding to a particular username.

    Requires the `username` parameter.

    Requires authentication.

    Returns the following data:
    {
        name: <user's name>
    }
    """
    good, response = check_params(['username'], request.query_params)
    if not good:
        return response

    try:
        friend = get_user_model().objects.get(username=request.query_params['username'])
        try:
            rel = Friend.objects.get(owner=request.user, friend=friend)
            if rel.name is not None:
                return Response(build_response('Got name', {'name': rel.name}), status=200)
            return Response(build_response('Got name', {'name': f'{friend.first_name} {friend.last_name}'}),
                            status=200)
        except Friend.DoesNotExist:
            return Response(build_response('Got name', {'name': f'{friend.first_name} {friend.last_name}'}),
                            status=200)
    except get_user_model().DoesNotExist:
        return Response(build_response("Couldn't find user"), status=400)


@api_view(['DELETE'])
def delete_friend(request: Request, username) -> Response:
    """
    /v2/delete_friend/<str:username>/
    DELETE: This friend relationship will be lazy-deleted, and can be fully undone by adding the friend back.

    Requires authentication.

    Returns status 400 if the other user is not a friend, and no data.
    """
    try:
        with transaction.atomic():
            friend = Friend.objects.select_for_update().get(owner=request.user, friend__username=username)
            friend.deleted = True
            friend.save()
        return Response(build_response('Successfully deleted friend'), status=200)
    except Friend.DoesNotExist:
        return Response(build_response('Could not delete friend as you were not friends'), status=400)


@api_view(['DELETE'])
def delete_user_data(request: Request) -> Response:
    """
    /v2/delete_user/data/
    DELETE: Truly deletes all data associated with the authenticated user (not lazy deletion, cannot be
    undone). Includes references to the user other people have in their friend lists, etc.

    Requires `username` and `password` in addition to an authentication token.

    Requires authentication.

    Returns no data.
    """
    good, response = check_params(['username', 'password'], request.data)
    if not good:
        return response

    user = authenticate(username=request.data['username'], password=request.data['password'])
    if request.user.username != request.data['username'] or user is None:
        return Response(build_response('Forbidden'), status=403)

    get_user_model().objects.get(username=request.user.username).delete()
    return Response(build_response('Successfully deleted user data'), status=200)


class EditUserThrottle(UserRateThrottle):
    rate = '5/hour'


@api_view(['PUT'])
@throttle_classes([EditUserThrottle] if not settings.IS_TESTING else [])
def edit_user(request: Request) -> Response:
    """
    /v2/edit/
    PUT: Updates the corresponding fields for the authenticated user.

    Has 5 optional parameters: `first_name`, `last_name`, `email`, `photo`, `password`, and `old_password`.
    If `password` is provided, `old_password` must also be provided (returning status 400 if it is not), and it should
    be the password the user currently has - otherwise, will return status 401.

    The photo should base-64 encoded. Remember that EXIF data is not saved when encoding in base 64 - the server will
    not attempt to rotate the image.
    If the image is too large (more than 178,956,970 pixels, to be precise), will return status 413.
    The image will be resized and animations stripped. Transparency is preserved.

    This endpoint cannot be called more than 5 times per hour per user - exceeding this limit will result in status 429

    Requires authentication.

    Returns no data.
    """
    if 'password' in request.data and 'old_password' not in request.data:
        return Response(build_response('To update password, provide old password'), status=400)
    invalid_field = ''
    try:
        with transaction.atomic():
            photo = None
            user = get_user_model().objects.select_for_update().get(username=request.user.username)
            if 'username' in request.data:
                invalid_field = 'username'
                ASCIIUsernameValidator()(request.data['username'])
                user.username = request.data['username']
            if 'first_name' in request.data:
                user.first_name = request.data['first_name']
            if 'last_name' in request.data:
                user.last_name = request.data['last_name']
            if 'email' in request.data:
                invalid_field = 'email'
                validate_email(request.data['email'])
                user.email = request.data['email']
            if 'photo' in request.data:
                invalid_field = 'photo'
                temp_image: Image.Image = Image.open(io.BytesIO(base64.b64decode(request.data['photo'])))
                if temp_image.width > temp_image.height:
                    # image is wider than it is tall - size should be (128 * aspect ratio, 128)
                    size = ((Photo.PHOTO_SIZE * temp_image.width) // temp_image.height, Photo.PHOTO_SIZE)
                else:
                    # image is taller than it is wide - size should be (128, 128 * aspect ratio)
                    size = (Photo.PHOTO_SIZE, (Photo.PHOTO_SIZE * temp_image.height) // temp_image.width)
                temp_image = temp_image.resize(size=size, resample=Image.Resampling.LANCZOS)\
                    .crop(box=((size[0] - Photo.PHOTO_SIZE) // 2,  # we get the 128 x 128 square in the middle
                               (size[1] - Photo.PHOTO_SIZE) // 2,
                               (size[0] + Photo.PHOTO_SIZE) // 2,
                               (size[1] + Photo.PHOTO_SIZE) // 2))
                buffered = io.BytesIO()
                temp_image.save(buffered, format='PNG')
                photo, _ = Photo.objects.update_or_create(user=user, defaults={
                    'photo': base64.b64encode(buffered.getvalue()).decode()})
            if 'password' in request.data:
                if len(request.data['password']) >= 8:
                    check_pass = authenticate(username=request.user.username, password=request.data['old_password'])
                    if check_pass is not None:
                        user.set_password(request.data['password'])
                        Token.objects.get(user=user).delete()
                        FCMTokens.objects.filter(user=user).delete()
                    else:
                        raise PermissionDenied('Invalid password')
                else:
                    invalid_field = 'password'
                    raise ValidationError('Password was not long enough')
            user.save()
            if photo is not None:
                photo.save()
    except (ValidationError, UnidentifiedImageError, ValueError) as e:
        logger.info(str(e))
        return Response(build_response(f'Could not update user: invalid value for {invalid_field}: {e}'),
                        status=400)
    except PermissionDenied:
        return Response(build_response('Incorrect old password'), status=401)
    except IntegrityError:
        return Response(build_response('Username or email address in use'), status=400)
    except DecompressionBombError:
        return Response(build_response('Profile picture was too large'), status=413)
    return Response(build_response('User updated successfully'), status=200)


@api_view(['POST'])
def link_google_account(request: Request) -> Response:
    """
    /v2/link_google_account/
    POST: Link a user's username/password account to their Google account

    Requires their current password (`password`) and Google account id token (`id_token`)

    Requires authentication

    Returns 403 if the Google account token or the password is invalid
    Returns 400 if the Google account is already linked to another account
    No data
    """
    good, response = check_params(['password', 'id_token'], request.data)
    if not good:
        return response

    user = request.user
    token = request.data['id_token']

    check_pass = authenticate(username=request.user.username, password=request.data['password'])
    if check_pass is None:
        return Response(build_response('Incorrect old password'), status=403)

    try:
        with transaction.atomic():
            user.set_unusable_password()
            # Specify the CLIENT_ID of the app that accesses the backend:
            id_info = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)

            # ID token is valid. Get the user's Google Account ID from the decoded token.
            user_id = id_info['sub']
            user.google_id = user_id
            user.save()

    except ValueError:
        return Response(build_response('Invalid Google account'), status=403)
    except IntegrityError:
        return Response(build_response('Google account is already linked to another account'), status=400)

    return Response(build_response('Google account linked successfully'), status=200)


@api_view(['GET', 'HEAD'])
def get_user_info(request: Request) -> Response:
    """
    /v2/get_info/
    GET: Returns a data dump based on the user used to authenticate.

    Accepts no parameters.

    Requires authentication.

    On success, returns the following in the data field:
    {
        username: <user's username>,
        first_name: <user's first name or null>,
        last_name: <user's last name or null>,
        email: <user's email or null>,
        password_login: <boolean: true if user uses password for login, false if they use Google>,
        photo: <user's profile photo, base64 encoded, RGBA-8888, or null if not set>,
        friends: [
            {
                friend: <friend's username>,
                name: <friend's name or null>,
                sent: <number of messages sent to friend>,
                received: <number of messages received from friend>,
                last_message_id_sent: <the last alert id that was sent to this friend or null>,
                last_message_read: <whether the last message was read or not>,
                photo: <friend's profile photo, base64 encoded, RGBA-8888, or null if not set>
            },
            ...
        ]
    }
    """
    user = request.user
    friends = [flatten_friend(x) for x in Friend.objects
               .select_related('friend__photo')
               .filter(owner=user, deleted=False)]
    data = {
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'email': user.email,
        'password_login': user.google_id is None,
        'photo': user.photo.photo if hasattr(user, 'photo') else None,
        'friends': friends,
    }
    return Response(build_response('Got user data', data=data), status=200)


class AlertThrottle(UserRateThrottle):
    rate = '15/min'


@api_view(['POST'])
@throttle_classes([AlertThrottle] if not settings.IS_TESTING else [])
def send_alert(request: Request) -> Response:
    """
    /v2/send_alert/
    POST: Sends an alert with an optional message to a user. The user must have the authenticated user added as a friend
    for this to succeed.

    Requires `to` and `message` to be set as parameters. If `message` is 'null', the app should display the default "no
    message" alert.

    This endpoint cannot be called more than 15 times per minute per user - exceeding this limit will result in status
    429

    Requires authentication.

    Returns status 400 on error
    On success, returns the following data:
    {
        'id': <alert id>
    }
    """
    # unauthenticated requests should be denied automatically - test this
    good, response = check_params(['to'], request.data)
    if not good:
        return response

    to: str = request.data['to']

    alert_id = str(time.time())
    timestamp = int(time.time())
    try:
        friend = Friend.objects.get(owner__username=to, friend__username=request.user.username, deleted=False)
        friend.received += 1
        friend.save()
        friend, created = Friend.objects.get_or_create(owner__username=request.user.username, friend__username=to,
                                                       defaults={'deleted': True})
        friend.sent += 1
        friend.last_sent_alert_id = alert_id
        friend.last_sent_message_status = Friend.SENT
        friend.save()
    except Friend.DoesNotExist:
        return Response(build_response(f'Could not send message as {to} does not have you as a friend'),
                        status=403)

    tokens: QuerySet = FCMTokens.objects.filter(user__username=to)
    if not bool(tokens):
        return Response(build_response(f'Could not find devices belong to user {to}'), status=400)
    try:
        firebase_admin.initialize_app()
    except ValueError:
        logger.info('Firebase Admin app already initialized')

    at_least_one_success: bool = False
    for token in tokens:
        message = messaging.Message(
            data={
                'action': 'alert',
                'alert_id': alert_id,
                'alert_to': request.data['to'],
                'alert_from': request.user.username,
                'alert_message': str(request.data['message']) if 'message' in request.data else "None",
                'alert_timestamp': str(timestamp)
            },
            android=messaging.AndroidConfig(
                priority='high'
            ),
            token=token.fcm_token
        )

        try:
            messaging.send(message)
            at_least_one_success = True
        except InvalidArgumentError as e:
            logger.warning(f'An alert failed to send: {e.cause}')
        except UnregisteredError:
            token.delete()

    if not at_least_one_success:
        return Response(build_response(f"Unable to send message"), status=400)
    return Response(build_response("Successfully sent message", data={'id': alert_id}), status=200)


@api_view(['POST'])
def alert_delivered(request: Request) -> Response:
    """
    /v2/alert_delivered/
    POST: Sends a signal that an alert has been delivered.

    Requires `alert_id` and `from` parameters to be set.

    Requires authentication.

    Returns no data.
    """
    good, response = check_params(['alert_id', 'from'], request.data)
    if not good:
        return response

    try:
        with transaction.atomic():
            friend = Friend.objects.select_for_update().get(owner__username=request.data['from'],
                                                            friend__username=request.user.username,
                                                            last_sent_alert_id=request.data['alert_id'])
            if friend.last_sent_message_status == Friend.SENT:
                friend.last_sent_message_status = Friend.DELIVERED
                friend.save()
            else:
                return Response(build_response("Message was already read or delivered"))
    except Friend.DoesNotExist:
        return Response(build_response("Delivered message was not the last sent"))

    tokens: QuerySet = FCMTokens.objects.filter(user__username=request.data['from'])

    if not bool(tokens):
        logger.warning("Could not find tokens for recipient")
        return Response(build_response(f'An error occurred'), status=500)
    try:
        firebase_admin.initialize_app()
    except ValueError:
        logger.info('Firebase Admin app already initialized')

    at_least_one_success: bool = False
    for token in tokens:
        message = messaging.Message(
            data={
                'action': 'delivered',
                'alert_id': request.data['alert_id'],
                'username_to': request.user.username,
            },
            android=messaging.AndroidConfig(
                priority='normal'
            ),
            token=token.fcm_token
        )

        try:
            messaging.send(message)
            at_least_one_success = True
        except InvalidArgumentError as e:
            logger.warning(f'An alert failed to send: {e.cause}')
        except UnregisteredError:
            token.delete()

    if not at_least_one_success:
        return Response(build_response(f"Unable to send delivery status"), status=400)
    return Response(build_response("Successfully sent delivery status"), status=200)


@api_view(['POST'])
def alert_read(request: Request) -> Response:
    """
    /v2/alert_read/
    POST: Sends a signal to dismiss an alert on all of the user's other devices.

    Requires `alert_id`, `from`, and `fcm_token` parameters to be set.

    Requires authentication.

    Returns no data.
    """
    good, response = check_params(['alert_id', 'from', 'fcm_token'], request.data)
    if not good:
        return response

    try:
        with transaction.atomic():
            friend = Friend.objects.select_for_update().get(owner__username=request.data['from'],
                                                            friend__username=request.user.username,
                                                            last_sent_alert_id=request.data['alert_id'])
            if friend.last_sent_message_status != Friend.READ:
                friend.last_sent_message_status = Friend.READ
                friend.save()
            else:
                return Response(build_response("Message was already read"))
    except Friend.DoesNotExist:
        return Response(build_response("Read message was not the last sent"))

    tokens: QuerySet = FCMTokens.objects.filter(user__username=request.user.username).exclude(fcm_token=request.data[
        'fcm_token']).union(FCMTokens.objects.filter(user__username=request.data['from']))

    if not bool(tokens):
        logger.warning("Could not find tokens for recipient or the users' other devices")
        return Response(build_response(f'An error occurred'), status=500)
    try:
        firebase_admin.initialize_app()
    except ValueError:
        logger.info('Firebase Admin app already initialized')

    at_least_one_success: bool = False
    for token in tokens:
        message = messaging.Message(
            data={
                'action': 'read',
                'alert_id': request.data['alert_id'],
                'username_to': request.user.username,
            },
            android=messaging.AndroidConfig(
                priority='normal'
            ),
            token=token.fcm_token
        )

        try:
            messaging.send(message)
            at_least_one_success = True
        except InvalidArgumentError as e:
            logger.warning(f'An alert failed to send: {e.cause}')
        except UnregisteredError:
            token.delete()

    if not at_least_one_success:
        return Response(build_response(f"Unable to send read status"), status=400)
    return Response(build_response("Successfully sent read status"), status=200)


def check_params(expected: list, holder: Dict) -> Tuple[bool, Response]:
    missing: list = []
    for expect in expected:
        if expect not in holder:
            missing.append(expect)
    response = Response(build_response(f"Missing required parameter(s): {', '.join(missing)}"),
                        status=400) if len(missing) != 0 else Response()
    return len(missing) == 0, response


def build_response(message: str, data: Any = None, string: bool = False) -> dict:
    response = {
        "message": message,
        "data": data
    }
    if string:
        response = string_response(response)
    return response


def string_response(args: dict):
    return json.dumps(args)


def flatten_friend(friend: Friend):
    return {
        'friend': friend.friend.username,
        'name': friend.name or f'{friend.friend.first_name} {friend.friend.last_name}',
        'photo': friend.friend.photo.photo if hasattr(friend.friend, 'photo') else None,
        'sent': friend.sent,
        'received': friend.received,
        'last_message_id_sent': friend.last_sent_alert_id,
        'last_message_status': friend.get_last_sent_message_status_display(),
    }
