@echo off
setlocal
hostname
whoami
if /I not "%COMPUTERNAME%"=="CYBORG" (
  echo REFUSE: not Cyborg
  exit /b 2
)

set ROOT=C:\Users\siddu\Projects\corvex
if not exist "%ROOT%\corvex\contain\windows_firewall.py" (
  echo Missing checkout at %ROOT% — cloning
  mkdir C:\Users\siddu\Projects 2>nul
  where git >nul 2>&1
  if errorlevel 1 (
    echo git missing
    exit /b 2
  )
  git clone https://github.com/Siddarthb07/corvex.git "%ROOT%"
)

cd /d "%ROOT%"
git fetch --all --prune
git status -sb
python -m pip install -e ".[dev]" -q
set CORVEX_ROOT=%ROOT%
set CORVEX_CONTAIN=0
python scripts\cyborg_fw_isolate_smoke.py
set RC=%ERRORLEVEL%
echo SMOKE_EXIT=%RC%
exit /b %RC%
