#!/usr/bin/env bash

port=${1:-8002}

cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P
export DJANGO_SETTINGS_MODULE='attention_api.production'
pipenv run python3.9 -m hypercorn --bind localhost:"$port" attention_api.asgi:application
