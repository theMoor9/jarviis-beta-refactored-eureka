@echo off
set VENV_DIR=..\env

:: Controlla se la cartella dell'ambiente virtuale esiste
if not exist %VENV_DIR% (
    echo Creating the virtual environment...
    python -m venv %VENV_DIR%
    if %errorlevel% neq 0 (
        echo Error during virtual environment creation.
        pause
        exit /b %errorlevel%
    )
)

:: Attiva l'ambiente virtuale
call %VENV_DIR%\Scripts\activate
if %errorlevel% neq 0 (
    echo Error during virtual environment creation.
    pause
    exit /b %errorlevel%
)

:: Installa le dipendenze
python -m pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt >nul 2>&1
if %errorlevel% neq 0 (
    echo Error during dependency setup.
    pause
    exit /b %errorlevel%
)

:: Esegui il tuo script Python
python jarviis.py
if %errorlevel% neq 0 (
    echo Error during application execution.
    pause
    exit /b %errorlevel%
)

:: Disattiva l'ambiente virtuale
deactivate
if %errorlevel% neq 0 (
    echo Error during la deactivation of the virtual environment.
    pause
    exit /b %errorlevel%
)

:: Attendi la chiusura per vedere l'output
pause
