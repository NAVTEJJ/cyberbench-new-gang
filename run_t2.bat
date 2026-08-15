@echo off
set PATH=C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.venv\Scripts;C:\Program Files\Git\bin;%PATH%
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
set TERM=dumb
set NO_COLOR=1
cd /d C:\Users\NAVTEJ\Downloads\Cyber-Bench-main
C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.venv\Scripts\python.exe C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.agents\skills\build-cyberbench-task\scripts\workflow.py --manifest C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\tasksets\v3\incoming\100\.task-factory-runtime\task-factory.toml run-target --attempts 2 > C:\Users\NAVTEJ\AppData\Local\Temp\opencode\t2_out.txt 2> C:\Users\NAVTEJ\AppData\Local\Temp\opencode\t2_err.txt
