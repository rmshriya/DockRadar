$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

New-Item -ItemType Directory -Force "data" | Out-Null
New-Item -ItemType Directory -Force "config" | Out-Null

docker compose up --build -d
if ($LASTEXITCODE -ne 0) {
    throw "EgressEye did not start. Check that Docker Desktop is running, then inspect: docker compose logs"
}

Write-Host "EgressEye is starting. Open http://localhost:8501" -ForegroundColor Green
Write-Host "View service logs with: docker compose logs -f" -ForegroundColor DarkGray
