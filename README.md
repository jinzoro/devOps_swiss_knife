![Badge Alt Text](https://img.shields.io/badge/subject-status-color.svg)

# **DevOps Swiss Army Knife 🛠️**

## **Version: 1.4.0**

A versatile, terminal-based toolbox designed for DevOps engineers and systems administrators. This script consolidates a wide array of common system, network, file, container, Git, text processing, security, SSL/TLS, encryption, cloud, monitoring, package management, configuration, automation, and development utilities into a single, easy-to-use menu-driven interface. It also includes specific tools tailored for Windows environments.

The goal is to provide a comprehensive "Swiss Army Knife" for daily operational tasks, featuring clear organization, vibrant colors, and helpful emojis for an enhanced user experience.

## **✨ Features**

* **💻 System Information:** Get quick insights into your OS, CPU, memory, disk usage, and network interfaces.  
* **⚙️ Process Management:** List running processes and kill them by PID.  
* **🌐 Network Utilities:** Ping hosts, check open ports, trace routes, perform DNS lookups, view network connections, and make basic HTTP GET requests.  
* **📁 File Operations:** Find files, search for text within files (grep), list directory trees, create directories, delete files, and view file content.  
* **🐳 Container Utilities (Docker):** Manage Docker info, list containers and images, stop/remove containers, pull images, run simple containers, and view container logs.  
* **🌳 Git Utilities:** Check repository status, view commit logs, list branches, show staged diffs, pull, and push changes.  
* **📝 Text Processing Tools:** Format JSON and YAML, Base64 encode/decode, and URL encode/decode strings.  
* **🔒 Security Tools:** Generate MD5/SHA256 hashes, create strong passwords, and generate UUIDs.  
* **🔐 SSL/TLS Utilities:** View certificate details from files, check website SSL certificates, and generate self-signed certificates for testing.  
* **🔑 Encryption/Decryption Tools (Basic):** Perform simple XOR-based text encryption and decryption (for demonstration/obfuscation only, **not for sensitive data**).  
* **☁️ Cloud Utilities (Basic CLI):** Check for the presence of AWS, Azure, and GCP CLIs, and run basic commands like listing S3 buckets, Azure Resource Groups, and GCP Projects.  
* **📊 Monitoring & Logging Tools:** View system logs (syslog/event logs) and check service statuses.  
* **📦 Package Management Tools:** Update package lists, install, and remove packages using common OS-specific managers (apt, yum, brew, choco).  
* **🔧 Configuration Management Tools:** View, get, and set environment variables for the current session.  
* **🤖 Automation & Scheduling Tools:** List scheduled tasks (cron jobs/Windows Task Scheduler) and execute custom shell commands or scripts.  
* **🧑‍💻 Development Utilities:** Quickly check versions of Python, Node.js, and Java, and run npm install.  
* **🪟 Windows Specific Tools:** A dedicated section with tools specific to Windows environments, including listing/managing services, viewing network adapters, and listing local users. (This menu option is only active when run on Windows).

## **🚀 Setup and Installation**

1. **Save the Script:** Save the entire Python code into a single file, for example, devops\_swiss\_knife.py.  
2. **Install Python Dependencies:** Open your terminal or command prompt and install the required Python packages:  
   pip install colorama pyyaml

   * colorama: For colorful terminal output.  
   * pyyaml: For YAML formatting (optional, but recommended for full functionality).  
3. Ensure External Tools (Prerequisites):  
   Many functionalities rely on external command-line tools. Ensure they are installed and available in your system's PATH:  
   * openssl: For SSL/TLS utilities.  
   * docker: For Container utilities.  
   * git: For Git utilities.  
   * curl (or wget): For HTTP GET requests.  
   * netcat (nc or ncat): For basic port checks.  
   * tree: For directory tree listing (optional, ls \-R is a fallback).  
   * npm (Node.js): For Node.js development utilities.  
   * systemctl (Linux) / sc (Windows): For service management.  
   * aws, az, gcloud CLIs: For Cloud Utilities (install and configure as needed).  
   * crontab (Linux/macOS) / schtasks (Windows): For scheduled task management.

## **🏃 Usage**

To start the DevOps Swiss Army Knife, navigate to the directory where you saved devops\_swiss\_knife.py and run the script:

python devops\_swiss\_knife.py

Follow the interactive, menu-driven prompts to select and execute the desired tools.

## **🤝 Contributing**

Feel free to extend this toolbox\! If you have ideas for new tools or improvements:

1. Fork the repository (if hosted on GitHub).  
2. Create a new branch for your feature (git checkout \-b feature/your-feature-name).  
3. Add your new function(s) to the devops\_swiss\_knife.py file.  
4. Integrate your new function(s) into the display\_main\_menu() and main() functions.  
5. Update the VERSION constant.  
6. Test your changes thoroughly.  
7. Commit your changes (git commit \-m 'feat: Add new feature').  
8. Push to your branch (git push origin feature/your-feature-name).  
9. Open a Pull Request.

## **📄 License**

This project is open-source and available under the [Jinzoro License](https://www.google.com/search?q=LICENSE).
