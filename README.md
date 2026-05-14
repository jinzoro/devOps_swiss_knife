![Versatility](https://img.shields.io/badge/Capability-Versatile-indigo?style=for-the-badge&logo=python&logoColor=white) ![Professional Quality](https://img.shields.io/badge/Quality-Professional-purple?style=for-the-badge&logo=github&logoColor=white) ![Linux Compatible](https://img.shields.io/badge/OS-Linux-orange?style=for-the-badge&logo=linux&logoColor=white) ![Windows Compatible](https://img.shields.io/badge/OS-Windows-blue?style=for-the-badge&logo=windows&logoColor=white) ![Actively Developed](https://img.shields.io/badge/Status-Actively%20Developed-brightgreen?style=for-the-badge&logo=dev&logoColor=white)

# **DevOps Swiss Army Knife 🛠️**

## **Version: 2.0.0**

A versatile, terminal-based toolbox designed for DevOps engineers and systems administrators. This script consolidates a wide array of common system, network, file, container, Git, text processing, security, SSL/TLS, encryption, cloud, monitoring, package management, configuration, automation, development, and infrastructure utilities into a single, easy-to-use menu-driven interface. It also includes specific tools tailored for Windows environments.

The goal is to provide a comprehensive "Swiss Army Knife" for daily operational tasks, featuring clear organization, vibrant colors, and helpful emojis for an enhanced user experience.

## **✨ Features**

* **💻 System Information:** Get quick insights into your OS, CPU, memory, disk usage, inode usage, network interfaces, uptime, and logged-in users.
* **⚙️ Process Management:** List running processes, kill by PID, find processes by name, and view process trees.
* **🌐 Network Utilities:** Ping hosts, check/scan port ranges, trace routes, DNS lookups, HTTP GET/POST requests, Whois, Dig, routing table, ARP cache.
* **📁 File Operations:** Find files, grep text, directory tree, create/delete directories and files, view content, calculate MD5/SHA256 checksums, zip/unzip, and chmod.
* **🐳 Container Utilities (Docker):** Full container lifecycle (start/stop/restart/remove/exec/logs), pull/inspect images, Docker Compose (up/down/status), system prune.
* **🌳 Git Utilities:** Status, log, branches, diff, pull, push, add, commit, clone, checkout, stash (list/save/pop), tags, branch create/delete.
* **📝 Text Processing Tools:** Format/validate JSON and YAML, Base64/URL encode-decode, line/word/char count, JSON↔YAML conversion, string case converter.
* **🔒 Security Tools:** MD5/SHA256 hashing, cryptographically-secure password generation (via `secrets`), UUID generation, SSH key generation, SSH connection test, ssh-copy-id, UFW firewall management.
* **🔐 SSL/TLS Utilities:** View certificate details, check website SSL certs, generate self-signed certificates, check certificate expiration.
* **🔑 Encryption/Decryption Tools (Basic):** Simple XOR-based encryption/decryption (for demonstration only, **not for sensitive data**).
* **☁️ Cloud Utilities (Basic CLI):** AWS, Azure, and GCP CLI checks and basic commands (S3 buckets, Resource Groups, Projects, AWS identity).
* **📊 Monitoring & Logging Tools:** View system/custom log files, check service statuses, top CPU/memory processes snapshot.
* **📦 Package Management Tools:** Update, install, remove, search packages, and list installed packages (apt/yum/brew/choco).
* **🔧 Configuration Management Tools:** View/get/set environment variables, backup and restore files/directories.
* **🤖 Automation & Scheduling Tools:** List cron jobs, execute custom commands, run with delay, add/remove crontab entries.
* **🧑‍💻 Development Utilities:** Check versions (Python, Node.js, Java, Go, Rust, PHP), npm install, create Python venvs, install requirements.
* **☸️ Kubernetes Utilities:** List pods/deployments/services/nodes, describe pods, view logs, exec into pods.
* **🕸️ Web Server Utilities:** Check Nginx/Apache status, HTTP response headers, local port listening, config viewer, redirect testing, access/error log tailing, reload/restart.
* **🗄️ Database Utilities:** Check MySQL/PostgreSQL/SQL Server clients, run MySQL/PostgreSQL queries interactively, Redis CLI check and ping.
* **🖥️ Virtualization Utilities:** VirtualBox and Vagrant presence checks and VM listing.
* **🏗️ Terraform Utilities:** Full workflow — init, validate, plan, apply, destroy, show state, outputs, workspace management (with safety confirmations for destructive ops).
* **🪟 Windows Specific Tools:** Services, network adapters, local users/groups, DNS flush, installed programs, uptime, firewall rules, disk health, network shares, detailed process info, Windows Update status, disk space.

## **🚀 Setup and Installation**

1. **Save the Script:** Save the entire Python code into a single file, for example, devops\_swiss\_knife.py.  
2. **Install Python Dependencies:** Open your terminal or command prompt and install the required Python packages:  

```
   pip install colorama pyyaml
```

   * colorama: For colorful terminal output.  
   * pyyaml: For YAML formatting (optional, but recommended for full functionality).  
4. Ensure External Tools (Prerequisites):  
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

```
python devops_swiss_knife.py
```

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
