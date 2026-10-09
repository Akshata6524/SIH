$ErrorActionPreference = "Stop"

docker compose build api
if ($LASTEXITCODE -ne 0) {
    throw "docker compose build api failed"
}

docker save -o ulpf-offline.tar ulpf:offline
if ($LASTEXITCODE -ne 0) {
    throw "docker save failed"
}

Write-Output "Offline image bundle written to ulpf-offline.tar"
