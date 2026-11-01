$ErrorActionPreference = "Stop"

if (-not (Test-Path ".venv")) {
  python -m venv .venv
}
$python = Join-Path (Get-Location) ".venv\Scripts\python.exe"
& $python -m pip install --upgrade pip
& $python -m pip install -r requirements.txt

if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
  Write-Host "Created .env from .env.example. Add your private GNANI_API_KEY to .env to enable live features. Sample analysis works without it." -ForegroundColor Yellow
}

Write-Host "Starting SunoSafe at http://127.0.0.1:8000" -ForegroundColor Green
& $python -m uvicorn main:app --reload
