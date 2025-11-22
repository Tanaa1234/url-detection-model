#!/bin/bash

# URL Detection System - Quick Start Script

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║            URL MALICIOUSNESS DETECTION SYSTEM                ║"
echo "║                        QUICK START                           ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies if needed
echo "Installing/updating dependencies..."
pip install -r requirements.txt > /dev/null 2>&1

# Check if models exist
if [ ! -f "models/random_forest_model.joblib" ]; then
    echo ""
    echo "No trained models found. Starting training process..."
    echo "This will take several minutes..."
    python main.py --action train
else
    echo ""
    echo "Trained models found. Launching application..."
fi

# Launch the application
python main.py --action run