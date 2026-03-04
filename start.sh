#!/bin/bash

set -e

# shellcheck disable=SC2034
envfile="../env/$THIS_ENV/auth-source.env"

# validates envfile exist
if [[ ! -f "$envfile" ]]; then
    echo "[ERROR] $(realpath "$envfile") does not exist"
    exit 1
fi

set -a
# shellcheck disable=SC1090
source "$envfile"
set +a

uvicorn app:app --host "$SERVER_APPLICATION_HOST" --port "$SERVER_APPLICATION_PORT"  --reload