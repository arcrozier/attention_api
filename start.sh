#!/usr/bin/env bash

cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P
export DJANGO_SETTINGS_MODULE='attention_api.production'
./.venv/bin/python3.9 -m hypercorn --bind localhost:8002 attention_api.asgi:application
