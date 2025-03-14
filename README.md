# Linux GUI User/Group Manager

This project is a graphical user interface (GUI) application for managing users, groups, and filesystem permissions in a Linux environment. The system is designed to simplify the administration of users and groups and their associated file permissions.

## Table of Contents
- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [File Structure](#file-structure)
- [Dependencies](#dependencies)
- [Logging](#logging)
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
   cd linux_gui_manager
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python src/main.py
   ```

2. Follow the on-screen instructions to log in and access the appropriate admin dashboard.

## File Structure

```
linux_gui_manager/
├── docker/  # Docker-related files
│   ├── Dockerfile  # Dockerfile for SSH-enabled containers
│   ├── docker-compose.yml  # For multi-container setup
│   └── scripts/  # Scripts to automate container setup
├── src/
│   ├── gui/
│   │   ├── login_window.py
│   │   ├── pc_connection.py
│   │   ├── junior_dashboard.py
│   │   ├── senior_dashboard.py
│   │   └── virtual_pc_manager.py  # Manage Docker containers
│   ├── backend/
│   │   ├── auth_backend.py
│   │   ├── connection_backend.py
│   │   ├── junior_backend.py
│   │   ├── senior_backend.py
│   │   ├── virtual_pc_backend.py  # Backend for Docker container management
│   │   └── brute_force_prevention.py  # Brute-force prevention logic
│   └── main.py
├── logs/
│   ├── auth_logs.txt
│   ├── error_logs.txt
│   └── brute_force_logs.txt  # Logs for brute-force attempts
├── requirements.txt
└── README.md
```

## Dependencies

- Python 3.x
- Tkinter or PyQt
- Other dependencies can be found in `requirements.txt`

## Logging

Logs are stored in the `logs/` directory. It contains two files:
- `auth_logs.txt` for authentication attempts.
- `error_logs.txt` for system errors.

## Contributing

If you'd like to contribute to this project, feel free to open an issue or submit a pull request. Please ensure that any changes adhere to the project's coding standards.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
