$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$BasePython = $null
$BasePythonArgs = @()

if (Get-Command python -ErrorAction SilentlyContinue) {
    $BasePython = "python"
}
elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $BasePython = "py"
    $BasePythonArgs = @("-3")
}
else {
    throw "Python was not found. Install Python 3.11+ from https://www.python.org/downloads/windows/ and run this script again."
}

Push-Location $ProjectRoot
try {
    if (-not (Test-Path -LiteralPath $VenvPython)) {
        & $BasePython @BasePythonArgs -m venv .venv
    }

    & $VenvPython -m pip install --upgrade pip
    & $VenvPython -m pip install -r requirements-dev.txt
    & $VenvPython scripts\check_env.py
}
finally {
    Pop-Location
}
