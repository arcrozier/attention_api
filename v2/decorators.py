import functools
from typing import Callable, Iterable

from rest_framework.request import Request
from rest_framework.response import Response

from v2.utils import check_params


def check_params_wrapper(expected: Iterable, actual: dict, view: Callable[..., Response], request: Request, *args, **kwargs) -> Response:
    good, response = check_params(expected, actual)
    if good:
        return view(request, *args, **kwargs)
    return response


def require_params(*params):

    def decorator(view: Callable[..., Response]):

        @functools.wraps(view)
        def wrapper(request: Request, *args, **kwargs):
            return check_params_wrapper(params, request.data, view, request, *args, **kwargs)

        return wrapper

    return decorator


def require_query_params(*params):

    def decorator(view: Callable[..., Response]):

        @functools.wraps(view)
        def wrapper(request: Request, *args, **kwargs):
            return check_params_wrapper(params, request.query_params, view, request, *args, **kwargs)

        return wrapper

    return decorator
