#!/usr/bin/env sh
set -eu

docker load -i ulpf-offline.tar
docker compose up -d
