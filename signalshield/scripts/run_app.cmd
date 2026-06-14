@echo off
setlocal

set "PROJECT_ROOT=%~dp0.."
set "VENV_PYTHON=%PROJECT_ROOT%\.venv\Scripts\python.exe"

cd /d "%PROJECT_ROOT%"

if exist "%VENV_PYTHON%" (
  "%VENV_PYTHON%" -m streamlit run app.py
  exit /b %ERRORLEVEL%
)

where python >nul 2>nul
if %ERRORLEVEL%==0 (
  python -m streamlit run app.py
  exit /b %ERRORLEVEL%
)

where py >nul 2>nul
if %ERRORLEVEL%==0 (
  py -3 -m streamlit run app.py
  exit /b %ERRORLEVEL%
)

echo Python was not found. Run scripts\setup_dev.ps1 after installing Python 3.11+.
exit /b 1
