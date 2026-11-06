@echo off
setlocal
hostname
if /I not "%COMPUTERNAME%"=="CYBORG" (
  echo REFUSE not Cyborg
  exit /b 2
)
mkdir C:\Users\siddu\Projects\corvex 2>nul
cd /d C:\Users\siddu\Projects\corvex
python -c "import tarfile; tarfile.open(r'C:\Users\siddu\cyborg_sync.tgz').extractall(r'C:\Users\siddu\Projects\corvex'); print('extracted')"
python -m pip install -e . -q
set CORVEX_ROOT=C:\Users\siddu\Projects\corvex
set CORVEX_CONTAIN=0
python scripts\cyborg_fw_isolate_smoke.py
echo SMOKE_EXIT=%ERRORLEVEL%
exit /b %ERRORLEVEL%
