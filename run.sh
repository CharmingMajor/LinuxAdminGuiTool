#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python -m venv .venv
fi

source .venv/bin/activate

echo "Installing/updating dependencies..."
pip install -r requirements.txt --root-user-action=ignore

echo "Setting correct permissions for system files..."
chmod 664 /etc/group
chmod 664 /etc/passwd
chmod 600 /etc/shadow
chmod 664 /etc/gshadow 2>/dev/null || true
chmod 664 /etc/subuid 2>/dev/null || true
chmod 664 /etc/subgid 2>/dev/null || true

rm -f /etc/.pwd.lock 2>/dev/null || true
rm -f /etc/passwd.lock 2>/dev/null || true
rm -f /etc/shadow.lock 2>/dev/null || true
rm -f /etc/group.lock 2>/dev/null || true
rm -f /etc/gshadow.lock 2>/dev/null || true

export $(dbus-launch)

echo "Checking Docker service (for testing purposes - will bypass if not available)..."
if systemctl is-active --quiet docker; then
    echo "Docker is running."
else
    echo "Docker is not running (this is optional)."
fi

echo "Starting Linux GUI User/Group Manager..."
export QT_QPA_PLATFORM=xcb
export PYTHONPATH=$PYTHONPATH:$(pwd)
sudo python src/main.py