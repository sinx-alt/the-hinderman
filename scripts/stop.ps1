$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$runtime = Join-Path $root "data\runtime"
$processFile = Join-Path $runtime "processes.json"

if (-not (Test-Path $processFile)) {
    Write-Output "No prototype process list found."
    exit 0
}

$processes = Get-Content $processFile -Raw | ConvertFrom-Json
$targets = @(
    @{ Id = [int]$processes.backend_pid; Pattern = "gateway.main:app" },
    @{ Id = [int]$processes.dashboard_pid; Pattern = "http.server 5173" }
)
foreach ($target in $targets) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $($target.Id)" -ErrorAction SilentlyContinue
    if ($process -and $process.CommandLine -like "*$($target.Pattern)*") {
        Stop-Process -Id $target.Id -Force
        Write-Output "Stopped prototype process $($target.Id)."
    }
}
Remove-Item -LiteralPath $processFile -Force
