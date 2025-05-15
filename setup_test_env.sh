#!/bin/bash

# Make sure we're in the right directory
cd "$(dirname "$0")"

# Function to check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        echo "Error: Docker is not running or you don't have permission to use it"
        exit 1
    fi
}

# Function to show container status
show_status() {
    echo "Test Environment Status:"
    echo "------------------------"
    docker-compose ps
    echo -e "\nConnection Information:"
    echo "------------------------"
    echo "Test System 1:"
    echo "  Host: localhost"
    echo "  Port: 2222"
    echo "  Users:"
    echo "    - testuser (password: password123)"
    echo "    - adminuser (password: admin123) - has sudo rights"
    echo -e "\nTest System 2:"
    echo "  Host: localhost"
    echo "  Port: 2223"
    echo "  Users:"
    echo "    - testuser (password: password123)"
    echo "    - adminuser (password: admin123) - has sudo rights"
}

# Check if Docker is running
check_docker

case "$1" in
    "start")
        echo "Starting test environment..."
        docker-compose up -d
        sleep 2  # Wait for containers to start
        show_status
        ;;
    "stop")
        echo "Stopping test environment..."
        docker-compose down
        ;;
    "restart")
        echo "Restarting test environment..."
        docker-compose restart
        sleep 2  # Wait for containers to restart
        show_status
        ;;
    "status")
        show_status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        echo "  start   - Start the test environment"
        echo "  stop    - Stop the test environment"
        echo "  restart - Restart the test environment"
        echo "  status  - Show test environment status"
        exit 1
        ;;
esac 