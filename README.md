# N3xG3n Firewall Manager

![GitHub release (latest by date)](https://img.shields.io/github/v/release/Digital-Synergy2024/N3xG3n-Firewall-Manager)
![GitHub issues](https://img.shields.io/github/issues/Digital-Synergy2024/N3xG3n-Firewall-Manager)
![GitHub pull requests](https://img.shields.io/github/issues-pr/Digital-Synergy2024/N3xG3n-Firewall-Manager)
![GitHub license](https://img.shields.io/github/license/Digital-Synergy2024/N3xG3n-Firewall-Manager)
![GitHub stars](https://img.shields.io/github/stars/Digital-Synergy2024/N3xG3n-Firewall-Manager?style=social)

N3xG3n Firewall Manager is a comprehensive GUI-based tool for managing Windows Firewall settings. It provides an intuitive interface for configuring firewall rules, monitoring network traffic, and performing advanced network diagnostics. Designed for both novice and advanced users, this tool simplifies firewall management while offering powerful features.

---

![N3xG3n Firewall Manager Screenshot](N3xG3n_FrieWall_Manager.png)

---

## Table of Contents
1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [File Structure](#file-structure)
5. [Troubleshooting](#troubleshooting)
6. [Contributing](#contributing)
7. [Code of Conduct](#code-of-conduct)
8. [License](#license)
9. [Contact](#contact)

---

## Features

### **1. Firewall Management**
- Enable/Disable Firewall.
- Open/Close Specific Ports.
- Query Port Status.
- Reset Firewall to Default Settings.
- List Active Rules.
- Search/Delete Firewall Rules.

### **2. Predefined Port Profiles**
- Predefined configurations for:
  - Communication Tools (Zoom, Skype, Discord).
  - Game Servers (Minecraft, CS:GO, Fortnite, Valorant, etc.).
  - Development Tools (Docker, Jenkins, GitLab).
  - Database Servers (MySQL, PostgreSQL, MongoDB).
  - Web Servers (HTTP, HTTPS).

### **3. Backup and Restore**
- Backup Firewall Rules to a `.wfw` file.
- Restore Firewall Rules from a `.wfw` file.

### **4. Logs and Statistics**
- Export Logs.
- View Statistics (Total Rules, Allow Rules, Block Rules).

### **5. Advanced Features**
- Detect Port Conflicts.
- View Network Profile.
- Live Network Traffic Viewer.
- Execute Windows Commands (e.g., `ping`, `ipconfig`, `netstat`, `tracert`).
- Geo-IP Blocking.
- Firewall Rule Simulator.
- Generate and Export Reports.
- Port Scanning.
- Validate Firewall Rules.
- Malware Detection.
- View Active Connections.
- Manage Whitelist/Blacklist.
- Schedule Firewall Tasks.
- Monitor System Resources (CPU, Memory, Network Usage).
- Advanced Rule Management.
- Generate Security Audit Reports.

### **6. Customization**
- Set Color Theme.
- Create and Save Custom Themes.
- Multi-language Support.
- Customizable Dashboard.

---

## Installation

### **Prerequisites**
- **Python 3.10 or higher**: Ensure Python is installed on your system.
- **Dependencies**: Install the following Python libraries:
  - `bcrypt`
  - `tkinter` (comes with Python)
  - `json` (comes with Python)
  - `ctypes` (comes with Python)
  - `requests`
  - `packaging`
  - `psutil`
  - `matplotlib`
  - `pandas`

### **Steps**
1. Clone the repository:
   ```bash
   git clone https://github.com/Digital-Synergy2024/N3xG3n-Firewall-Manager.git
   cd N3xG3n-Firewall-Manager
   ```

2. Install dependencies:
   ```bash
   pip install bcrypt
   ```
   ```
   pip install requests
   ```
   ```
   pip install packaging
   ```
   ```
   pip install psutil
   ```
   ```
   pip install matplotlib
   ```
   ```
   pip install pandas
   ```

4. Build the standalone executable (optional):
   - Run the `build_firewall_manager.bat` script to create a standalone `.exe` file:
     ```bash
     build_firewall_manager.bat
     ```

5. Start the application:
   - Run the `N3xG3n_FireWall_Manager.exe` to start the tool
     ```bash
     N3xG3n_FireWall_Manager.exe
     ```

---

## Usage

### **Main Menu**
- The main menu provides access to all features, including firewall management, predefined profiles, logs, and advanced tools.

### **Predefined Port Profiles**
- Navigate to the "Predefined Port Profiles" section to enable or disable profiles for common applications.

### **Logs and Statistics**
- Export logs or view statistics about the current firewall rules from the "Settings" section.

### **Help Menu**
- Access detailed instructions for using the application.

---

## File Structure

- **`N3xG3n_FireWall_Manager.py`**: The main Python script for the application.
- **`build_firewall_manager.bat`**: Batch script to build the standalone executable using PyInstaller.
- **`icon.ico`**: Icon file for the application.
- **`users.json`**: Stores user credentials (created at runtime).
- **`firewall_manager.txt`**: Action log file (created at runtime).
- **`error_log.txt`**: Error log file (created at runtime).

---

## Troubleshooting

### **Common Issues**
1. **Missing Python Installation**:
   - The application checks for Python and prompts the user to install it if missing.

2. **Missing Dependencies**:
   - The application checks for required dependencies and installs them if missing.

3. **Administrator Privileges**:
   - The application must be run with administrator privileges. If not, it will relaunch itself with elevated permissions.

4. **Icon Not Displaying**:
   - Ensure the `icon.ico` file is in the same directory as the application.

---

## Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add feature-name"
   ```
4. Push to your branch:
   ```bash
   git push origin feature-name
   ```
5. Open a pull request.

### Guidelines
- Follow the [Code of Conduct](#code-of-conduct).
- Ensure your code is well-documented and adheres to the project's coding standards.
- Write clear and concise commit messages.
- Test your changes thoroughly before submitting a pull request.

---

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to jarrodz@digital-synergy.org.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Contact

For questions or support, please contact:
- **Email**: jarrodz@digital-synergy.org
- **GitHub**: [Digital-Synergy2024](https://github.com/Digital-Synergy2024)
- **Website**:
[Digital-Synergy.org](https://Digital-Synergy.org)
