$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$runtime = Join-Path $root "data\runtime"
$python = (& py -3 -c "import sys; print(sys.executable)" 2>$null).Trim()
$node = Get-Command node.exe -ErrorAction SilentlyContinue

if (-not $python -or -not (Test-Path $python)) {
    throw "Python 3 was not found. Install Python 3.11 or newer and retry."
}
$dashboard = Join-Path $root "dashboard"
$dist = Join-Path $dashboard "dist"
New-Item -ItemType Directory -Path $runtime -Force | Out-Null

if (-not (Test-Path (Join-Path $dist "index.html"))) {
    if (-not $node) {
        throw "Node.js is required to build the dashboard."
    }
    $nodeDirectory = Split-Path $node.Source
    $npm = Join-Path $nodeDirectory "npm.cmd"
    $env:Path = "$nodeDirectory;$env:Path"
    Push-Location $dashboard
    try {
        & $npm run build
        if ($LASTEXITCODE -ne 0) {
            throw "Dashboard build failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}

foreach ($port in 8000, 5173) {
    if (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue) {
        throw "Port $port is already in use. Stop the existing service before starting the prototype."
    }
}

$env:LLM_MODE = "ollama"
$env:LLM_MODEL = "ollama/qwen3.5:4b"
$env:OLLAMA_API_BASE = "http://localhost:11434"
$env:LLM_TIMEOUT_SECONDS = "180"
$env:LLM_MAX_TOKENS = "256"
$env:OCR_MODE = "tesseract"
$tesseract = Get-Command tesseract.exe -ErrorAction SilentlyContinue
if ($tesseract) {
    $env:TESSERACT_CMD = $tesseract.Source
}
elseif (Test-Path "C:\Program Files\Tesseract-OCR\tesseract.exe") {
    $env:TESSERACT_CMD = "C:\Program Files\Tesseract-OCR\tesseract.exe"
}
$env:JWT_SECRET = "hinderman-local-demo-secret-change-before-network"

$apiProcess = Start-Process -FilePath $python -ArgumentList @(
    "-m", "uvicorn", "gateway.main:app", "--host", "127.0.0.1", "--port", "8000"
) -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput (
    Join-Path $runtime "api.log"
) -RedirectStandardError (Join-Path $runtime "api-error.log") -PassThru

try {
    $webProcess = Start-Process -FilePath $python -ArgumentList @(
        "-m", "http.server", "5173", "--bind", "127.0.0.1"
    ) -WorkingDirectory $dist -WindowStyle Hidden -RedirectStandardOutput (
        Join-Path $runtime "dashboard.log"
    ) -RedirectStandardError (Join-Path $runtime "dashboard-error.log") -PassThru

    $deadline = (Get-Date).AddSeconds(45)
    $healthy = $false
    while ((Get-Date) -lt $deadline) {
        try {
            $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 2
            $page = Invoke-WebRequest -Uri "http://127.0.0.1:5173/" -TimeoutSec 2
            if ($health.status -eq "ok" -and $health.llm_ready -and $page.StatusCode -eq 200) {
                $healthy = $true
                break
            }
        }
        catch {
            Start-Sleep -Seconds 1
        }
    }
    if (-not $healthy) {
        throw "Prototype readiness check failed. Inspect data\runtime\api-error.log and dashboard-error.log."
    }

    @{
        backend_pid = $apiProcess.Id
        dashboard_pid = $webProcess.Id
        started_at = (Get-Date).ToString("o")
    } | ConvertTo-Json | Set-Content -Path (Join-Path $runtime "processes.json")

    Write-Output "The Hinderman is running."
    Write-Output "Dashboard: http://localhost:5173"
    Write-Output "API docs:  http://localhost:8000/docs"
    Write-Output "LLM:       $($health.configured_model) (ready)"
}
catch {
    foreach ($process in @($apiProcess, $webProcess)) {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
    throw
}
