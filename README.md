# Linux Admin GUI Tool (Work in progress)

A modern graphical user interface for Linux system administration, designed to simplify remote system management with a clean, professional dashboard UI.

## Key Features

- **Secure Remote Management**: SSH-based remote system management with password or private key authentication
- **Role-Based Access Control**: Different interfaces for junior and senior administrators
- **System Monitoring**: Real-time resource usage monitoring (CPU, memory, disk, network)
- **User Management**: Create, modify, and delete user accounts
- **Network Configuration**: Interface configuration, firewall rules, and monitoring
- **Log Analysis**: Integrated log viewer with filtering capabilities
- **System Updates**: Update management with approval workflow
- **Backup Management**: Create, restore, and manage system backups
- **Permission Management**: File and directory permission control
- **Task Reporting**: Built-in task reporting for junior administrators

## Role-Based Dashboards

### Senior Administrator Dashboard
- Full access to all system functions
- Unrestricted system configuration
- Advanced monitoring capabilities
- Backup creation and restoration
- Remote system administration
- Permission management
- Advanced firewall configuration

### Junior Administrator Dashboard
- Read-only access to critical systems
- Limited configuration options
- Basic system monitoring
- Task reporting functionality
- Permissions management (non-system files only)
- Update checking (requires approval for installation)

## Screenshots

[Screenshots will be added here]

## Technical Details

- Built with Python 3.8+ and PySide6 (Qt)
- Secure remote management via Paramiko (SSH)
- Role-based access control
- Real-time system monitoring
- Customizable dark/light theme support

## Installation

### Prerequisites

- Python 3.8+
- Linux-based system (host and target)
- SSH access to target systems
- Root privileges (for system operations)

### Standard Installation

```bash
# Clone the repository
git clone https://github.com/CharmingMajor/LinuxAdminGuiTool.git
cd LinuxAdminGuiTool

# Run the setup script (requires root permissions)
sudo ./run.sh
```

### Development Setup

```bash
# Clone the repository
git clone https://github.com/CharmingMajor/LinuxAdminGuiTool.git
cd LinuxAdminGuiTool

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python src/main.py
```

### Docker Setup

The application can also be run in a Docker container:

```bash
# Build and run with docker-compose
docker-compose up
```

## Usage

1. Launch the application
2. Log in with appropriate credentials
3. Connect to a remote system using SSH
4. Navigate the dashboard to manage system resources

## Requirements

See `requirements.txt` for a complete list of dependencies.

## License

MIT License
