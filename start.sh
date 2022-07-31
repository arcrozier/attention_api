#!/usr/bin/env bash

port=${1:-8002}
db_credentials=${1:"/var/local/db_credentials/attention_api.env"}

cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P
export DJANGO_SETTINGS_MODULE='attention_api.production'
export DB_CREDENTIALS_FILE=$db_credentials
pipenv run python3.9 -m hypercorn --bind localhost:"$port" attention_api.asgi:application
