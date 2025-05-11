#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# Install/update dependencies
echo "Installing/updating dependencies..."
pip install -r requirements.txt

# Ensure proper permissions for system files and ownership
echo "Setting correct permissions for system files..."
chmod 664 /etc/group
chmod 664 /etc/passwd
chmod 600 /etc/shadow
# Linux distros may use different file access methods, provide fallbacks for permissions
chmod 664 /etc/gshadow 2>/dev/null || true
chmod 664 /etc/subuid 2>/dev/null || true
chmod 664 /etc/subgid 2>/dev/null || true

# Lock files sometimes cause issues, remove any stale ones
rm -f /etc/.pwd.lock 2>/dev/null || true
rm -f /etc/passwd.lock 2>/dev/null || true
rm -f /etc/shadow.lock 2>/dev/null || true
rm -f /etc/group.lock 2>/dev/null || true
rm -f /etc/gshadow.lock 2>/dev/null || true

# Set up DBus environment
export $(dbus-launch)

# Check Docker service (for testing purposes)
echo "Checking Docker service (for testing purposes - will bypass if not available)..."
if systemctl is-active --quiet docker; then
    echo "Docker is running."
else
    echo "Docker is not running (this is optional)."
fi

# Start the application with proper environment
echo "Starting Linux GUI User/Group Manager..."
export QT_QPA_PLATFORM=xcb
export PYTHONPATH=$PYTHONPATH:$(pwd)
python src/main.py 