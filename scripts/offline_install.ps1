$ErrorActionPreference = "Stop"

docker load -i ulpf-offline.tar
if ($LASTEXITCODE -ne 0) {
    throw "docker load failed"
}

docker compose up -d
if ($LASTEXITCODE -ne 0) {
    throw "docker compose up failed"
}
