@echo off
REM Starts BOTH websites in two separate windows (Windows).
REM First time only:  python -m venv venv  ->  venv\Scripts\activate  ->  pip install -r requirements.txt
cd /d "%~dp0"
set "PY=python"
if exist "venv\Scripts\python.exe" set "PY=venv\Scripts\python.exe"

start "WEBSITE 1 - LabMart store (port 5000)" cmd /k ""%PY%" run_shop.py"
timeout /t 3 /nobreak >nul
start "WEBSITE 2 - CyberSim Lab (port 5001)" cmd /k ""%PY%" run_lab.py"
timeout /t 3 /nobreak >nul
start "" "http://127.0.0.1:5000/admin/login"
start "" "http://127.0.0.1:5001/login"
