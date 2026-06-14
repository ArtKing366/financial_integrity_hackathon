$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$PythonArgs = @()

if (Test-Path -LiteralPath $Python) {
    $PythonArgs = @()
}
elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $Python = "python"
    $PythonArgs = @()
}
elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $Python = "py"
    $PythonArgs = @("-3")
}
else {
    throw "Python was not found. Install Python 3.11+ or run scripts\setup_dev.ps1 after installing it."
}

Push-Location $ProjectRoot
try {
    & $Python @PythonArgs -m http.server 8765 --directory fixtures
}
finally {
    Pop-Location
}
