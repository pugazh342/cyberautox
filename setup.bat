@echo off
:: CyberAutoX Windows Installer
set PYTHON=python
set VENV=venv

:: Clone SQLMap if not exists
if not exist "sqlmap" (
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
)

:: Create virtualenv
%PYTHON% -m venv %VENV%
call %VENV%\Scripts\activate.bat

:: Install dependencies
pip install -r requirements.txt

:: Create payloads directory if not exists
if not exist "resources\payloads" mkdir resources\payloads

:: Create sample XSS payloads
echo ^<script^>alert(1)^</script^> > resources\payloads\xss.txt
echo "onload=alert(1)" >> resources\payloads\xss.txt

echo Setup completed! Activate virtualenv with: call %VENV%\Scripts\activate.bat