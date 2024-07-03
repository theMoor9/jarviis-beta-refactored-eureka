#!/bin/bash

VENV_DIR="../env"

# Controlla se la cartella dell'ambiente virtuale esiste
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating the virtual environment..."
    python3 -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo "Error during virtual environment creation."
        read -p "Press enter to exit..."
        exit 1
    fi
fi

# Attiva l'ambiente virtuale
source "$VENV_DIR/bin/activate"
if [ $? -ne 0 ]; then
    echo "Error during virtual environment creation."
    read -p "Press enter to exit..."
    exit 1
fi

# Installa le dipendenze
python -m pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error during dependency setup."
    read -p "Press enter to exit..."
    exit 1
fi

# Esegui il tuo script Python
python3 jarviis.py
if [ $? -ne 0 ]; then
    echo "Error during application execution."
    read -p "Press enter to exit..."
    exit 1
fi

# Disattiva l'ambiente virtuale
deactivate
if [ $? -ne 0 ]; then
    echo "Error during la deactivation of the virtual environment."
    read -p "Press enter to exit..."
    exit 1
fi

# Attendi la chiusura per vedere l'output
read -p "Press enter to exit..."