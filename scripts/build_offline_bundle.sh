#!/usr/bin/env sh
set -eu

docker compose build api
docker save -o ulpf-offline.tar ulpf:offline
printf '%s\n' "Offline image bundle written to ulpf-offline.tar"
