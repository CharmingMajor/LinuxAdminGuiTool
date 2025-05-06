#!/bin/bash

# Linux GUI User/Group Manager Launcher Script

# Ensure we're in the project directory
cd "$(dirname "$0")"

# Ensure the logs directory exists
mkdir -p logs

# Activate virtual environment if it exists, or create it
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python -m venv .venv
fi

# Activate the virtual environment
source .venv/bin/activate

# Install/update dependencies
echo "Installing/updating dependencies..."
pip install -r requirements.txt

# Check if Docker is running and bypass if not available for testing
echo "Checking Docker service (for testing purposes - will bypass if not available)..."
if command -v docker &> /dev/null; then
    if docker info &> /dev/null; then
        echo "Docker is running."
        
        # Start Docker containers (comment out for testing)
        # echo "Starting Docker containers..."
        # if command -v docker-compose &> /dev/null; then
        #     docker-compose up -d
        # else
        #     echo "Warning: docker-compose is not installed. Please install it to use container functionality."
        # fi
    else
        echo "Warning: Docker is installed but not running. Starting without container functionality."
    fi
else
    echo "Warning: Docker is not installed. Starting without container functionality."
fi

# Run the application
echo "Starting Linux GUI User/Group Manager..."
python -m src.main 