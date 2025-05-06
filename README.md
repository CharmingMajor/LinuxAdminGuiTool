# Linux GUI User/Group Manager

This project is a graphical user interface (GUI) application for managing users, groups, and filesystem permissions in a Linux environment. The system is designed to simplify the administration of users and groups and their associated file permissions.

## Table of Contents
- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [File Structure](#file-structure)
- [Dependencies](#dependencies)
- [Docker Integration](#docker-integration)
- [Logging](#logging)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## Overview

The Linux GUI User/Group Manager is aimed at streamlining the management of Linux users and groups, including setting permissions on files and directories. The system is designed with different user roles in mind, including junior and senior admins, with specific functionalities and dashboards tailored for each.

## Installation

To get started with the project, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/CharmingMajor/LinuxAdminGuiTool.git
   ```

2. Navigate into the project directory:
   ```bash
   cd LinuxAdminGuiTool
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. (Optional) Set up Docker for virtual PC simulation:
   ```bash
   docker-compose up -d
   ```

## Usage

1. Run the application:
   ```bash
   python src/main.py
   ```

2. Login with the appropriate credentials:
   - Junior Admin: username `junior`, password `junior123`
   - Senior Admin: username `senior`, password `senior123`

3. Use the appropriate dashboard according to your role:

### Junior Admin Dashboard
- View container status
- View logs
- View configuration
- Monitor system health

### Senior Admin Dashboard
- Full container management (start/stop/restart)
- SSH into containers
- User and group management
- File permissions management
- Container cleanup and inspection

## Features

### User Management
- Create, modify, and delete users
- Set user home directories and shells
- Assign users to groups

### Group Management
- Create, modify, and delete groups
- Assign users to groups
- Set group permissions

### File System Permissions
- Change file and directory permissions
- Set file ownership
- Modify access modes (read, write, execute)

### Virtual PC Management
- Docker-based PC simulation
- SSH connectivity
- Container lifecycle management
- System monitoring and logs

### Security Features
- Role-based access control
- Brute force prevention
- Secure authentication
- Logging of security events

## File Structure

```
linux_gui_manager/
├── docker/  # Docker-related files
│   ├── Dockerfile  # Dockerfile for SSH-enabled containers
│   ├── docker-compose.yml  # For multi-container setup
│   └── scripts/  # Scripts to automate container setup
├── src/
│   ├── gui/
│   │   ├── login_window.py  # Authentication interface
│   │   ├── pc_connection.py  # SSH connectivity
│   │   ├── junior_dashboard.py  # Junior admin interface
│   │   ├── senior_dashboard.py  # Senior admin interface
│   │   ├── virtual_pc_manager.py  # Docker container management
│   │   ├── user_management.py  # User/group management interface
│   │   ├── permissions_manager.py  # File permissions interface
│   │   └── pc_config_dashboard.py  # Container configuration
│   ├── backend/
│   │   ├── auth_backend.py  # Authentication logic
│   │   ├── connection_backend.py  # SSH connection handling
│   │   ├── junior_backend.py  # Junior admin capabilities
│   │   ├── senior_backend.py  # Senior admin capabilities
│   │   └── virtual_pc_backend.py  # Docker API integration
│   └── main.py  # Application entry point
├── logs/  # Log files
│   ├── app.log  # Application logs
│   ├── auth_logs.txt  # Authentication logs
│   └── brute_force_logs.txt  # Security logs
├── requirements.txt  # Python dependencies
└── README.md  # Project documentation
```

## Dependencies

- Python 3.x
- Docker (for container simulation)
- Tkinter (GUI framework)
- Docker Python SDK
- Paramiko (SSH connectivity)
- Additional dependencies are listed in `requirements.txt`

## Docker Integration

The application uses Docker to simulate virtual PCs for management training. The integration provides:

1. Multiple isolated Linux environments
2. SSH connectivity for remote administration
3. Realistic system management scenarios
4. Safe testing environment for permissions and user management

To start the Docker containers:
```bash
docker-compose up -d
```

## Logging

Logs are stored in the `logs/` directory. It contains various log files:
- `app.log` - General application logs
- `auth_logs.txt` - Authentication attempts
- `brute_force_logs.txt` - Potential security breaches

## Security

- Brute force prevention with IP and account locking
- Password hashing for secure storage
- Role-based access control for different admin levels
- Comprehensive logging of security events

## Contributing

If you'd like to contribute to this project, feel free to open an issue or submit a pull request. Please ensure that any changes adhere to the project's coding standards.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
