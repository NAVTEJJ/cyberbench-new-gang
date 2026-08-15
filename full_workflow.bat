@echo off
set PATH=C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.venv\Scripts;C:\Program Files\Git\bin;%PATH%
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
set TERM=dumb
set NO_COLOR=1
cd /d C:\Users\NAVTEJ\Downloads\Cyber-Bench-main
echo === INIT ===
C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.venv\Scripts\python.exe C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.agents\skills\build-cyberbench-task\scripts\workflow.py --manifest C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\tasksets\v3\incoming\100\.task-factory-runtime\task-factory.toml init
echo === VALIDATE ===
C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.venv\Scripts\python.exe C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.agents\skills\build-cyberbench-task\scripts\workflow.py --manifest C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\tasksets\v3\incoming\100\.task-factory-runtime\task-factory.toml validate
echo === ORACLE ===
C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.venv\Scripts\python.exe C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.agents\skills\build-cyberbench-task\scripts\workflow.py --manifest C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\tasksets\v3\incoming\100\.task-factory-runtime\task-factory.toml oracle
echo === RECORD FAIRNESS ===
C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.venv\Scripts\python.exe C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.agents\skills\build-cyberbench-task\scripts\workflow.py --manifest C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\tasksets\v3\incoming\100\.task-factory-runtime\task-factory.toml record-fairness --file tasksets/v3/incoming/100/.task-factory-runtime/workflow/fairness.json
echo === RECORD DISCLOSURE ===
C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.venv\Scripts\python.exe C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.agents\skills\build-cyberbench-task\scripts\workflow.py --manifest C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\tasksets\v3\incoming\100\.task-factory-runtime\task-factory.toml record-disclosure --file tasksets/v3/incoming/100/.task-factory-runtime/workflow/disclosure.json --reviewer-kind isolated_agent
echo === RUN TARGET 3 ATTEMPTS ===
C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.venv\Scripts\python.exe C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.agents\skills\build-cyberbench-task\scripts\workflow.py --manifest C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\tasksets\v3\incoming\100\.task-factory-runtime\task-factory.toml run-target --attempts 3
echo === QUALIFY ===
C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.venv\Scripts\python.exe C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\.agents\skills\build-cyberbench-task\scripts\workflow.py --manifest C:\Users\NAVTEJ\Downloads\Cyber-Bench-main\tasksets\v3\incoming\100\.task-factory-runtime\task-factory.toml qualify
echo === DONE ===