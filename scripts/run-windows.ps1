Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    Write-Host "Virtual environment not found. Running the installer..." -ForegroundColor Yellow
    & (Join-Path $PSScriptRoot "install-windows.ps1")
}

if (-not (Test-Path $Python)) {
    throw "Virtual environment setup failed. Run .\scripts\install-windows.ps1 and review the error output."
}

Write-Host "Starting Password Security Suite..." -ForegroundColor Green
Write-Host "Open http://127.0.0.1:5000 in your browser."
Write-Host "Press Ctrl+C in this terminal to stop the server."

& $Python (Join-Path $ProjectRoot "app.py")
