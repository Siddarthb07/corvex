@echo off
hostname
whoami
python -c "import corvex,inspect,os; print(corvex.__file__)"
where corvex
net session >nul 2>&1 && echo ADMIN=yes || echo ADMIN=no
dir /b "%USERPROFILE%\.corvex" 2>nul
dir /s /b C:\Users\siddu\*corvex* 2>nul | findstr /i "pyproject.toml setup.cfg" | more +0
