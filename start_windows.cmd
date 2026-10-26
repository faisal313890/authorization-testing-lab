@echo off
cd /d "%~dp0"
py -3.12 server.py
if errorlevel 1 (
  echo.
  echo Could not start the lab. Confirm Python 3.12 is installed.
  echo If port 8820 is in use, run: set AUTH_LAB_PORT=8821
  pause
)
