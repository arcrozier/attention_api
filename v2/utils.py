import json
from typing import Any, Iterable

from rest_framework.response import Response

from v2.models import User


def check_params(expected: Iterable, holder: dict) -> tuple[bool, Response]:
    missing: list = []
    for expect in expected:
        if expect not in holder:
            missing.append(expect)
    response = Response(
        build_response(f"Missing required parameter{'' if len(missing) == 1 else 's'}: {', '.join(missing)}"),
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


def flatten_friend(friend: User):
    return {
        'friend': friend.friend.username,
        'name': friend.name or f'{friend.friend.first_name} {friend.friend.last_name}',
        'photo': friend.friend.photo.photo if hasattr(friend.friend, 'photo') else None,
        'sent': friend.sent,
        'received': friend.received,
        'last_message_id_sent': friend.last_sent_alert_id,
        'last_message_status': friend.get_last_sent_message_status_display(),
    }
