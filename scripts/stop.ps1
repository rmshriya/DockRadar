$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
docker compose down
if ($LASTEXITCODE -ne 0) {
    throw "Could not stop EgressEye."
}
Write-Host "EgressEye stopped. Local policy and event history are preserved." -ForegroundColor Green
