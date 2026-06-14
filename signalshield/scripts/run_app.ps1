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
    throw "Python was not found. Run scripts\setup_dev.ps1 after installing Python 3.11+."
}

Push-Location $ProjectRoot
try {
    & $Python @PythonArgs -m streamlit run app.py
}
finally {
    Pop-Location
}
