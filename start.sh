#!/usr/bin/env bash

cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P
export DJANGO_SETTINGS_MODULE='attention_api.production'
source .venv/bin/activate
hypercorn --bind localhost:8002 attention_api.asgi:application
