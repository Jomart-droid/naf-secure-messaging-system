@echo off
cd /d %~dp0
python scriptsootstrap_env.py
python run.py
pause
