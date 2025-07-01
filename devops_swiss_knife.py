import os
import subprocess
import sys
import platform
import json
import base64
import hashlib
import random
import string
import uuid # For generating UUIDs
from datetime import datetime
import urllib.parse # For URL encoding/decoding

# --- Third-party libraries (install if not present) ---
# For colors: pip install colorama
# For YAML parsing (optional): pip install pyyaml
try:
    from colorama import Fore, Style, init
    init(autoreset=True) # Automatically reset colors after each print
except ImportError:
    print("Colorama not found. Please install it: pip install colorama")
    class NoColor:
        def __getattr__(self, name):
            return ''
    Fore = NoColor()
    Style = NoColor()

try:
    import yaml
except ImportError:
    print("PyYAML not found. YAML formatting will be basic. Install it for full functionality: pip install pyyaml")
    yaml = None

# --- Configuration & Constants ---
APP_NAME = "DevOps Swiss Army Knife 🛠️"
VERSION = "1.4.0" # Updated version for new categories

# Emojis for better visual organization
EMOJI = {
    "system": "💻",
    "process": "⚙️",
    "network": "�",
    "file": "📁",
    "container": "🐳",
    "git": "🌳",
    "text": "📝",
    "security": "🔒",
    "ssl": "🔐", # New emoji for SSL/TLS
    "encrypt": "🔑", # New emoji for Encryption
    "cloud": "☁️", # New emoji for Cloud Utilities
    "monitor": "📊", # New emoji for Monitoring & Logging
    "package": "📦", # New emoji for Package Management
    "config": "🔧", # New emoji for Configuration Management
    "automation": "🤖", # New emoji for Automation & Scheduling
    "dev": "🧑‍💻", # New emoji for Development Utilities
    "windows": "🪟", # New emoji for Windows Specific Tools
    "exit": "👋",
    "menu": "📖",
    "success": "✅",
    "error": "❌",
    "info": "ℹ️",
    "warning": "⚠️",
    "input": "➡️",
    "loading": "⏳",
    "separator": "---",
    "bullet": "•",
    "create": "➕",
    "delete": "🗑️",
    "run": "▶️",
    "pull": "⬇️",
    "push": "⬆️",
}

# Colors for output
COLOR = {
    "header": Fore.CYAN + Style.BRIGHT,
    "menu_option": Fore.GREEN,
    "prompt": Fore.YELLOW,
    "info": Fore.BLUE,
    "success": Fore.GREEN,
    "error": Fore.RED + Style.BRIGHT,
    "warning": Fore.YELLOW,
    "output": Fore.WHITE,
    "reset": Style.RESET_ALL,
}

# --- Helper Functions ---

def print_header(title):
    """Prints a styled header for sections."""
    print(f"\n{COLOR['header']}{EMOJI['separator']} {title} {EMOJI['separator']}{COLOR['reset']}")

def print_message(message, msg_type="info"):
    """Prints a styled message based on type."""
    if msg_type == "info":
        print(f"{COLOR['info']}{EMOJI['info']} {message}{COLOR['reset']}")
    elif msg_type == "success":
        print(f"{COLOR['success']}{EMOJI['success']} {message}{COLOR['reset']}")
    elif msg_type == "error":
        print(f"{COLOR['error']}{EMOJI['error']} {message}{COLOR['reset']}")
    elif msg_type == "warning":
        print(f"{COLOR['warning']}{EMOJI['warning']} {message}{COLOR['reset']}")
    else:
        print(message)

def run_command(command, shell=True, capture_output=True, text=True, check=False):
    """
    Runs a shell command and returns its output or handles errors.
    Args:
        command (str or list): The command to execute.
        shell (bool): Whether to execute in a shell.
        capture_output (bool): Whether to capture stdout/stderr.
        text (bool): Whether to decode stdout/stderr as text.
        check (bool): If True, raise CalledProcessError on non-zero exit code.
    Returns:
        str: The output of the command if successful, None otherwise.
    """
    try:
        print_message(f"{EMOJI['loading']} Executing: {command}", "info")
        result = subprocess.run(
            command,
            shell=shell,
            capture_output=capture_output,
            text=text,
            check=check,
            encoding='utf-8', # Ensure consistent encoding
            errors='replace' # Replace unencodable characters
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print_message(f"Command failed with exit code {result.returncode}:", "error")
            if result.stdout:
                print_message(f"Stdout:\n{result.stdout.strip()}", "error")
            if result.stderr:
                print_message(f"Stderr:\n{result.stderr.strip()}", "error")
            return None
    except FileNotFoundError:
        print_message(f"Command '{command.split()[0]}' not found. Is it installed and in your PATH?", "error")
        return None
    except Exception as e:
        print_message(f"An unexpected error occurred: {e}", "error")
        return None

# --- Tool Functions ---

def display_system_info():
    """Displays various system information."""
    print_header(f"{EMOJI['system']} System Information")

    print_message(f"{EMOJI['bullet']} OS: {platform.system()} {platform.release()} ({platform.version()})")
    print_message(f"{EMOJI['bullet']} Architecture: {platform.machine()}")
    print_message(f"{EMOJI['bullet']} Node Name: {platform.node()}")
    print_message(f"{EMOJI['bullet']} Python Version: {platform.python_version()}")
    print_message(f"{EMOJI['bullet']} Current User: {os.getenv('USER') or os.getenv('USERNAME')}")

    # Common Linux/macOS commands
    if platform.system() in ["Linux", "Darwin"]:
        print_message(f"\n{EMOJI['info']} CPU Info (lscpu/sysctl):", "info")
        cpu_info = run_command("lscpu" if platform.system() == "Linux" else "sysctl -n machdep.cpu.brand_string")
        print(COLOR['output'] + (cpu_info if cpu_info else "N/A") + COLOR['reset'])

        print_message(f"\n{EMOJI['info']} Memory Usage (free -h):", "info")
        mem_info = run_command("free -h")
        print(COLOR['output'] + (mem_info if mem_info else "N/A") + COLOR['reset'])

        print_message(f"\n{EMOJI['info']} Disk Usage (df -h):", "info")
        disk_info = run_command("df -h")
        print(COLOR['output'] + (disk_info if disk_info else "N/A") + COLOR['reset'])

        print_message(f"\n{EMOJI['info']} Network Interfaces (ip a/ifconfig):", "info")
        net_info = run_command("ip a" if platform.system() == "Linux" else "ifconfig")
        print(COLOR['output'] + (net_info if net_info else "N/A") + COLOR['reset'])
    elif platform.system() == "Windows":
        print_message(f"\n{EMOJI['info']} System Info (systeminfo):", "info")
        sys_info = run_command("systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\" /C:\"Total Physical Memory\"")
        print(COLOR['output'] + (sys_info if sys_info else "N/A") + COLOR['reset'])

        print_message(f"\n{EMOJI['info']} IP Configuration (ipconfig):", "info")
        ip_config = run_command("ipconfig /all")
        print(COLOR['output'] + (ip_config if ip_config else "N/A") + COLOR['reset'])
    else:
        print_message("Detailed system info commands are not implemented for this OS.", "warning")

    print_message(f"\n{EMOJI['success']} System information displayed.", "success")

def manage_processes():
    """Provides basic process management utilities."""
    print_header(f"{EMOJI['process']} Process Management")

    while True:
        print(f"\n{COLOR['menu_option']}1. List all processes{COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. Kill a process by PID{COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            print_message(f"\n{EMOJI['info']} Listing processes (ps aux):", "info")
            if platform.system() in ["Linux", "Darwin"]:
                processes = run_command("ps aux")
            elif platform.system() == "Windows":
                processes = run_command("tasklist")
            else:
                processes = "Not supported on this OS."
            print(COLOR['output'] + (processes if processes else "N/A") + COLOR['reset'])
            print_message(f"{EMOJI['success']} Process list displayed.", "success")
        elif choice == '2':
            pid = input(f"{COLOR['prompt']}{EMOJI['input']} Enter PID to kill: {COLOR['reset']}").strip()
            if pid.isdigit():
                if platform.system() in ["Linux", "Darwin"]:
                    kill_cmd = f"kill -9 {pid}"
                elif platform.system() == "Windows":
                    kill_cmd = f"taskkill /F /PID {pid}"
                else:
                    print_message("Killing processes not supported on this OS.", "error")
                    continue

                result = run_command(kill_cmd)
                if result is not None:
                    print_message(f"{EMOJI['success']} Process {pid} killed successfully.", "success")
                else:
                    print_message(f"{EMOJI['error']} Failed to kill process {pid}.", "error")
            else:
                print_message(f"{EMOJI['warning']} Invalid PID. Please enter a number.", "warning")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

def network_utilities():
    """Provides basic network utilities."""
    print_header(f"{EMOJI['network']} Network Utilities")

    while True:
        print(f"\n{COLOR['menu_option']}1. Ping a host{COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. Check open port on a host (basic){COLOR['reset']}")
        print(f"{COLOR['menu_option']}3. Trace route to a host{COLOR['reset']}")
        print(f"{COLOR['menu_option']}4. DNS Lookup (nslookup){COLOR['reset']}")
        print(f"{COLOR['menu_option']}5. View Network Connections (netstat){COLOR['reset']}")
        print(f"{COLOR['menu_option']}6. Make a Basic HTTP GET Request (curl){COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            host = input(f"{COLOR['prompt']}{EMOJI['input']} Enter host to ping (e.g., google.com): {COLOR['reset']}").strip()
            if host:
                ping_cmd = f"ping -c 4 {host}" if platform.system() != "Windows" else f"ping {host}"
                ping_output = run_command(ping_cmd)
                print(COLOR['output'] + (ping_output if ping_output else "Ping failed or host unreachable.") + COLOR['reset'])
                print_message(f"{EMOJI['success']} Ping test completed.", "success")
            else:
                print_message(f"{EMOJI['warning']} Host cannot be empty.", "warning")
        elif choice == '2':
            host = input(f"{COLOR['prompt']}{EMOJI['input']} Enter host to check (e.g., example.com): {COLOR['reset']}").strip()
            port = input(f"{COLOR['prompt']}{EMOJI['input']} Enter port to check (e.g., 80, 443, 22): {COLOR['reset']}").strip()

            if host and port.isdigit():
                if platform.system() in ["Linux", "Darwin"]:
                    check_cmd = f"nc -vz {host} {port}"
                elif platform.system() == "Windows":
                    check_cmd = f"powershell -command \"Test-NetConnection -ComputerName {host} -Port {port}\""
                else:
                    print_message("Port checking not supported on this OS.", "error")
                    continue

                print_message(f"{EMOJI['loading']} Checking port {port} on {host}...", "info")
                check_output = run_command(check_cmd)
                print(COLOR['output'] + (check_output if check_output else "Port check failed.") + COLOR['reset'])
                if check_output and ("succeeded" in check_output or "open" in check_output or "succeeded" in check_output.lower()):
                    print_message(f"{EMOJI['success']} Port {port} on {host} appears to be OPEN.", "success")
                else:
                    print_message(f"{EMOJI['error']} Port {port} on {host} appears to be CLOSED or unreachable.", "error")
            else:
                print_message(f"{EMOJI['warning']} Invalid host or port.", "warning")
        elif choice == '3':
            host = input(f"{COLOR['prompt']}{EMOJI['input']} Enter host to trace (e.g., google.com): {COLOR['reset']}").strip()
            if host:
                trace_cmd = f"traceroute {host}" if platform.system() != "Windows" else f"tracert {host}"
                trace_output = run_command(trace_cmd)
                print(COLOR['output'] + (trace_output if trace_output else "Traceroute failed or host unreachable.") + COLOR['reset'])
                print_message(f"{EMOJI['success']} Traceroute completed.", "success")
            else:
                print_message(f"{EMOJI['warning']} Host cannot be empty.", "warning")
        elif choice == '4':
            hostname = input(f"{COLOR['prompt']}{EMOJI['input']} Enter hostname for DNS lookup (e.g., example.com): {COLOR['reset']}").strip()
            if hostname:
                nslookup_cmd = f"nslookup {hostname}"
                nslookup_output = run_command(nslookup_cmd)
                print(COLOR['output'] + (nslookup_output if nslookup_output else "DNS lookup failed.") + COLOR['reset'])
                print_message(f"{EMOJI['success']} DNS lookup completed.", "success")
            else:
                print_message(f"{EMOJI['warning']} Hostname cannot be empty.", "warning")
        elif choice == '5':
            print_message(f"\n{EMOJI['info']} Viewing Network Connections (netstat):", "info")
            if platform.system() in ["Linux", "Darwin"]:
                netstat_output = run_command("netstat -tulnp") # TCP, UDP, listening, numeric, programs
            elif platform.system() == "Windows":
                netstat_output = run_command("netstat -ano") # All connections, numeric, process ID
            else:
                netstat_output = "Not supported on this OS."
            print(COLOR['output'] + (netstat_output if netstat_output else "N/A") + COLOR['reset'])
            print_message(f"{EMOJI['success']} Network connections displayed.", "success")
        elif choice == '6':
            url = input(f"{COLOR['prompt']}{EMOJI['input']} Enter URL for HTTP GET request (e.g., http://example.com): {COLOR['reset']}").strip()
            if url:
                curl_output = run_command(f"curl -s -o /dev/null -w '%{{http_code}}' {url}" if platform.system() != "Windows" else f"curl -s -o NUL -w '%{{http_code}}' {url}")
                if curl_output:
                    print_message(f"\n{EMOJI['success']} HTTP Status Code for {url}: {COLOR['output']}{curl_output}{COLOR['reset']}", "success")
                    # Optionally, fetch full content
                    fetch_content = input(f"{COLOR['prompt']}{EMOJI['input']} Fetch full content? (y/n): {COLOR['reset']}").strip().lower()
                    if fetch_content == 'y':
                        full_content = run_command(f"curl -s {url}")
                        if full_content:
                            print_message(f"\n{EMOJI['info']} Full Content:\n{COLOR['output']}{full_content[:500]}... (truncated){COLOR['reset']}", "info")
                        else:
                            print_message(f"{EMOJI['error']} Failed to fetch full content.", "error")
                else:
                    print_message(f"{EMOJI['error']} Failed to make HTTP GET request. Is curl installed?", "error")
            else:
                print_message(f"{EMOJI['warning']} URL cannot be empty.", "warning")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

def file_operations():
    """Provides basic file system operations."""
    print_header(f"{EMOJI['file']} File Operations")

    while True:
        print(f"\n{COLOR['menu_option']}1. Find files by name (current directory){COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. Search for text in files (grep - current directory){COLOR['reset']}")
        print(f"{COLOR['menu_option']}3. List directory tree (tree){COLOR['reset']}")
        print(f"{COLOR['menu_option']}4. {EMOJI['create']} Create a directory{COLOR['reset']}")
        print(f"{COLOR['menu_option']}5. {EMOJI['delete']} Delete a file{COLOR['reset']}")
        print(f"{COLOR['menu_option']}6. View File Content (tail/cat){COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            filename_pattern = input(f"{COLOR['prompt']}{EMOJI['input']} Enter filename pattern (e.g., *.log, config.yaml): {COLOR['reset']}").strip()
            if filename_pattern:
                find_cmd = f"find . -name '{filename_pattern}'"
                find_output = run_command(find_cmd)
                print(COLOR['output'] + (find_output if find_output else "No files found.") + COLOR['reset'])
                print_message(f"{EMOJI['success']} File search completed.", "success")
            else:
                print_message(f"{EMOJI['warning']} Filename pattern cannot be empty.", "warning")
        elif choice == '2':
            search_text = input(f"{COLOR['prompt']}{EMOJI['input']} Enter text to search for: {COLOR['reset']}").strip()
            if search_text:
                if platform.system() in ["Linux", "Darwin"]:
                    grep_cmd = f"grep -r '{search_text}' ."
                elif platform.system() == "Windows":
                    grep_cmd = f"findstr /S /I /C:\"{search_text}\" .\\*" # /S: subdirectories, /I: case-insensitive, /C: exact phrase
                else:
                    print_message("Text search not supported on this OS.", "error")
                    continue

                grep_output = run_command(grep_cmd)
                print(COLOR['output'] + (grep_output if grep_output else "No matches found.") + COLOR['reset'])
                print_message(f"{EMOJI['success']} Text search completed.", "success")
            else:
                print_message(f"{EMOJI['warning']} Search text cannot be empty.", "warning")
        elif choice == '3':
            print_message(f"\n{EMOJI['info']} Listing directory tree (tree/dir /s /b):", "info")
            if platform.system() in ["Linux", "Darwin"]:
                tree_output = run_command("tree -L 2" if run_command("which tree") else "ls -R") # Use tree if available, else ls -R
            elif platform.system() == "Windows":
                tree_output = run_command("cmd /c \"dir /s /b\"") # Basic recursive listing
            else:
                tree_output = "Not supported on this OS."
            print(COLOR['output'] + (tree_output if tree_output else "N/A") + COLOR['reset'])
            print_message(f"{EMOJI['success']} Directory tree displayed.", "success")
        elif choice == '4':
            dir_name = input(f"{COLOR['prompt']}{EMOJI['input']} Enter directory name to create: {COLOR['reset']}").strip()
            if dir_name:
                try:
                    os.makedirs(dir_name, exist_ok=True)
                    print_message(f"{EMOJI['success']} Directory '{dir_name}' created successfully.", "success")
                except OSError as e:
                    print_message(f"{EMOJI['error']} Error creating directory '{dir_name}': {e}", "error")
            else:
                print_message(f"{EMOJI['warning']} Directory name cannot be empty.", "warning")
        elif choice == '5':
            file_to_delete = input(f"{COLOR['prompt']}{EMOJI['input']} Enter file path to delete: {COLOR['reset']}").strip()
            if file_to_delete:
                try:
                    if os.path.exists(file_to_delete):
                        os.remove(file_to_delete)
                        print_message(f"{EMOJI['success']} File '{file_to_delete}' deleted successfully.", "success")
                    else:
                        print_message(f"{EMOJI['warning']} File '{file_to_delete}' not found.", "warning")
                except OSError as e:
                    print_message(f"{EMOJI['error']} Error deleting file '{file_to_delete}': {e}", "error")
            else:
                print_message(f"{EMOJI['warning']} File path cannot be empty.", "warning")
        elif choice == '6':
            file_path = input(f"{COLOR['prompt']}{EMOJI['input']} Enter path to file to view: {COLOR['reset']}").strip()
            if file_path:
                if os.path.exists(file_path):
                    if platform.system() in ["Linux", "Darwin"]:
                        view_cmd = f"cat {file_path}"
                    elif platform.system() == "Windows":
                        view_cmd = f"type {file_path}"
                    else:
                        print_message("File content viewing not supported on this OS.", "error")
                        continue
                    
                    file_content = run_command(view_cmd)
                    if file_content:
                        print_message(f"\n{EMOJI['info']} Content of '{file_path}':\n{COLOR['output']}{file_content}{COLOR['reset']}", "info")
                    else:
                        print_message(f"{EMOJI['warning']} File '{file_path}' is empty or could not be read.", "warning")
                else:
                    print_message(f"{EMOJI['warning']} File '{file_path}' not found.", "warning")
            else:
                print_message(f"{EMOJI['warning']} File path cannot be empty.", "warning")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

def container_utilities():
    """Provides basic Docker container utilities."""
    print_header(f"{EMOJI['container']} Container Utilities (Docker)")

    # Check if Docker is running
    docker_status = run_command("docker info", check=False)
    if docker_status is None or "Cannot connect to the Docker daemon" in docker_status:
        print_message(f"{EMOJI['error']} Docker daemon is not running or not accessible. Please start Docker.", "error")
        return

    while True:
        print(f"\n{COLOR['menu_option']}1. Show Docker info{COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. List all containers (running and stopped){COLOR['reset']}")
        print(f"{COLOR['menu_option']}3. List all images{COLOR['reset']}")
        print(f"{COLOR['menu_option']}4. Stop a container by name/ID{COLOR['reset']}")
        print(f"{COLOR['menu_option']}5. Remove a container by name/ID{COLOR['reset']}")
        print(f"{COLOR['menu_option']}6. {EMOJI['pull']} Pull a Docker image{COLOR['reset']}")
        print(f"{COLOR['menu_option']}7. {EMOJI['run']} Run a simple Docker container{COLOR['reset']}")
        print(f"{COLOR['menu_option']}8. View Container Logs{COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            print_message(f"\n{EMOJI['info']} Docker Info:", "info")
            info = run_command("docker info")
            print(COLOR['output'] + (info if info else "Failed to get Docker info.") + COLOR['reset'])
            print_message(f"{EMOJI['success']} Docker info displayed.", "success")
        elif choice == '2':
            print_message(f"\n{EMOJI['info']} Listing all containers:", "info")
            containers = run_command("docker ps -a")
            print(COLOR['output'] + (containers if containers else "No containers found.") + COLOR['reset'])
            print_message(f"{EMOJI['success']} Containers listed.", "success")
        elif choice == '3':
            print_message(f"\n{EMOJI['info']} Listing all images:", "info")
            images = run_command("docker images")
            print(COLOR['output'] + (images if images else "No images found.") + COLOR['reset'])
            print_message(f"{EMOJI['success']} Images listed.", "success")
        elif choice == '4':
            container_id = input(f"{COLOR['prompt']}{EMOJI['input']} Enter container name or ID to stop: {COLOR['reset']}").strip()
            if container_id:
                stop_result = run_command(f"docker stop {container_id}")
                if stop_result is not None:
                    print_message(f"{EMOJI['success']} Container '{container_id}' stopped successfully.", "success")
                else:
                    print_message(f"{EMOJI['error']} Failed to stop container '{container_id}'.", "error")
            else:
                print_message(f"{EMOJI['warning']} Container name/ID cannot be empty.", "warning")
        elif choice == '5':
            container_id = input(f"{COLOR['prompt']}{EMOJI['input']} Enter container name or ID to remove: {COLOR['reset']}").strip()
            if container_id:
                remove_result = run_command(f"docker rm {container_id}")
                if remove_result is not None:
                    print_message(f"{EMOJI['success']} Container '{container_id}' removed successfully.", "success")
                else:
                    print_message(f"{EMOJI['error']} Failed to remove container '{container_id}'.", "error")
            else:
                print_message(f"{EMOJI['warning']} Container name/ID cannot be empty.", "warning")
        elif choice == '6':
            image_name = input(f"{COLOR['prompt']}{EMOJI['input']} Enter image name to pull (e.g., ubuntu:latest, nginx): {COLOR['reset']}").strip()
            if image_name:
                pull_result = run_command(f"docker pull {image_name}")
                if pull_result is not None:
                    print_message(f"{EMOJI['success']} Image '{image_name}' pulled successfully.", "success")
                else:
                    print_message(f"{EMOJI['error']} Failed to pull image '{image_name}'.", "error")
            else:
                print_message(f"{EMOJI['warning']} Image name cannot be empty.", "warning")
        elif choice == '7':
            image_name = input(f"{COLOR['prompt']}{EMOJI['input']} Enter image name to run (e.g., hello-world, alpine/git): {COLOR['reset']}").strip()
            container_name = input(f"{COLOR['prompt']}{EMOJI['input']} Enter a name for the container (optional): {COLOR['reset']}").strip()
            command_to_run = input(f"{COLOR['prompt']}{EMOJI['input']} Enter command to run inside container (optional, e.g., /bin/sh): {COLOR['reset']}").strip()

            if image_name:
                run_cmd = f"docker run --rm" # --rm automatically removes container on exit
                if container_name:
                    run_cmd += f" --name {container_name}"
                run_cmd += f" {image_name}"
                if command_to_run:
                    run_cmd += f" {command_to_run}"

                print_message(f"{EMOJI['loading']} Running container from image '{image_name}'...", "info")
                run_result = run_command(run_cmd)
                if run_result is not None:
                    print_message(f"{EMOJI['success']} Container from '{image_name}' ran successfully.", "success")
                    print(COLOR['output'] + run_result + COLOR['reset'])
                else:
                    print_message(f"{EMOJI['error']} Failed to run container from '{image_name}'.", "error")
            else:
                print_message(f"{EMOJI['warning']} Image name cannot be empty.", "warning")
        elif choice == '8':
            container_id = input(f"{COLOR['prompt']}{EMOJI['input']} Enter container name or ID to view logs: {COLOR['reset']}").strip()
            if container_id:
                log_output = run_command(f"docker logs {container_id}")
                if log_output is not None:
                    print_message(f"\n{EMOJI['success']} Logs for container '{container_id}':\n{COLOR['output']}{log_output}{COLOR['reset']}", "success")
                else:
                    print_message(f"{EMOJI['error']} Failed to get logs for container '{container_id}'.", "error")
            else:
                print_message(f"{EMOJI['warning']} Container name/ID cannot be empty.", "warning")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

def git_utilities():
    """Provides basic Git repository utilities."""
    print_header(f"{EMOJI['git']} Git Utilities")

    # Check if current directory is a Git repo
    git_root = run_command("git rev-parse --show-toplevel", check=False)
    if git_root is None:
        print_message(f"{EMOJI['error']} Not a Git repository. Please navigate to a Git repo directory.", "error")
        return
    else:
        print_message(f"{EMOJI['info']} Current Git repo: {git_root}", "info")

    while True:
        print(f"\n{COLOR['menu_option']}1. Git Status{COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. Git Log (last 5 commits){COLOR['reset']}")
        print(f"{COLOR['menu_option']}3. Git Branch (local and remote){COLOR['reset']}")
        print(f"{COLOR['menu_option']}4. Git Diff (staged){COLOR['reset']}")
        print(f"{COLOR['menu_option']}5. {EMOJI['pull']} Git Pull (fetch and merge){COLOR['reset']}")
        print(f"{COLOR['menu_option']}6. {EMOJI['push']} Git Push (current branch){COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            print_message(f"\n{EMOJI['info']} Git Status:", "info")
            status = run_command("git status")
            print(COLOR['output'] + (status if status else "Failed to get Git status.") + COLOR['reset'])
            print_message(f"{EMOJI['success']} Git status displayed.", "success")
        elif choice == '2':
            print_message(f"\n{EMOJI['info']} Git Log (last 5 commits):", "info")
            log = run_command("git log --oneline -5")
            print(COLOR['output'] + (log if log else "Failed to get Git log.") + COLOR['reset'])
            print_message(f"{EMOJI['success']} Git log displayed.", "success")
        elif choice == '3':
            print_message(f"\n{EMOJI['info']} Git Branches:", "info")
            branches_local = run_command("git branch")
            branches_remote = run_command("git branch -r")
            print(COLOR['output'] + "--- Local Branches ---\n" + (branches_local if branches_local else "N/A") + "\n--- Remote Branches ---\n" + (branches_remote if branches_remote else "N/A") + COLOR['reset'])
            print_message(f"{EMOJI['success']} Git branches displayed.", "success")
        elif choice == '4':
            print_message(f"\n{EMOJI['info']} Git Diff (staged changes):", "info")
            diff = run_command("git diff --staged")
            print(COLOR['output'] + (diff if diff else "No staged changes to diff.") + COLOR['reset'])
            print_message(f"{EMOJI['success']} Git diff displayed.", "success")
        elif choice == '5':
            print_message(f"\n{EMOJI['info']} Performing Git Pull...", "info")
            pull_result = run_command("git pull")
            if pull_result is not None:
                print(COLOR['output'] + pull_result + COLOR['reset'])
                print_message(f"{EMOJI['success']} Git Pull completed.", "success")
            else:
                print_message(f"{EMOJI['error']} Git Pull failed.", "error")
        elif choice == '6':
            print_message(f"\n{EMOJI['info']} Performing Git Push...", "info")
            push_result = run_command("git push")
            if push_result is not None:
                print(COLOR['output'] + push_result + COLOR['reset'])
                print_message(f"{EMOJI['success']} Git Push completed.", "success")
            else:
                print_message(f"{EMOJI['error']} Git Push failed. Ensure your branch is configured to push to an upstream remote.", "error")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

def text_processing_tools():
    """Provides text processing utilities."""
    print_header(f"{EMOJI['text']} Text Processing Tools")

    while True:
        print(f"\n{COLOR['menu_option']}1. Format JSON (pretty print){COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. Format YAML (pretty print){COLOR['reset']}")
        print(f"{COLOR['menu_option']}3. Base64 Encode{COLOR['reset']}")
        print(f"{COLOR['menu_option']}4. Base64 Decode{COLOR['reset']}")
        print(f"{COLOR['menu_option']}5. URL Encode{COLOR['reset']}")
        print(f"{COLOR['menu_option']}6. URL Decode{COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            json_input = input(f"{COLOR['prompt']}{EMOJI['input']} Paste JSON string here: {COLOR['reset']}").strip()
            try:
                parsed_json = json.loads(json_input)
                pretty_json = json.dumps(parsed_json, indent=4)
                print_message(f"\n{EMOJI['success']} Formatted JSON:\n{COLOR['output']}{pretty_json}{COLOR['reset']}", "success")
            except json.JSONDecodeError as e:
                print_message(f"{EMOJI['error']} Invalid JSON: {e}", "error")
        elif choice == '2':
            if yaml:
                yaml_input = input(f"{COLOR['prompt']}{EMOJI['input']} Paste YAML string here: {COLOR['reset']}").strip()
                try:
                    parsed_yaml = yaml.safe_load(yaml_input)
                    pretty_yaml = yaml.dump(parsed_yaml, indent=2, default_flow_style=False)
                    print_message(f"\n{EMOJI['success']} Formatted YAML:\n{COLOR['output']}{pretty_yaml}{COLOR['reset']}", "success")
                except yaml.YAMLError as e:
                    print_message(f"{EMOJI['error']} Invalid YAML: {e}", "error")
            else:
                print_message(f"{EMOJI['warning']} PyYAML not installed. Cannot format YAML. Please install it: pip install pyyaml", "warning")
        elif choice == '3':
            text_to_encode = input(f"{COLOR['prompt']}{EMOJI['input']} Enter text to Base64 encode: {COLOR['reset']}").strip()
            if text_to_encode:
                encoded_bytes = base64.b64encode(text_to_encode.encode('utf-8'))
                encoded_string = encoded_bytes.decode('utf-8')
                print_message(f"\n{EMOJI['success']} Base64 Encoded:\n{COLOR['output']}{encoded_string}{COLOR['reset']}", "success")
            else:
                print_message(f"{EMOJI['warning']} Input cannot be empty.", "warning")
        elif choice == '4':
            text_to_decode = input(f"{COLOR['prompt']}{EMOJI['input']} Enter Base64 string to decode: {COLOR['reset']}").strip()
            if text_to_decode:
                try:
                    decoded_bytes = base64.b64decode(text_to_decode)
                    decoded_string = decoded_bytes.decode('utf-8')
                    print_message(f"\n{EMOJI['success']} Base64 Decoded:\n{COLOR['output']}{decoded_string}{COLOR['reset']}", "success")
                except Exception as e:
                    print_message(f"{EMOJI['error']} Invalid Base64 string: {e}", "error")
            else:
                print_message(f"{EMOJI['warning']} Input cannot be empty.", "warning")
        elif choice == '5':
            text_to_url_encode = input(f"{COLOR['prompt']}{EMOJI['input']} Enter text to URL encode: {COLOR['reset']}").strip()
            if text_to_url_encode:
                encoded_url = urllib.parse.quote_plus(text_to_url_encode)
                print_message(f"\n{EMOJI['success']} URL Encoded:\n{COLOR['output']}{encoded_url}{COLOR['reset']}", "success")
            else:
                print_message(f"{EMOJI['warning']} Input cannot be empty.", "warning")
        elif choice == '6':
            text_to_url_decode = input(f"{COLOR['prompt']}{EMOJI['input']} Enter URL encoded string to decode: {COLOR['reset']}").strip()
            if text_to_url_decode:
                try:
                    decoded_url = urllib.parse.unquote_plus(text_to_url_decode)
                    print_message(f"\n{EMOJI['success']} URL Decoded:\n{COLOR['output']}{decoded_url}{COLOR['reset']}", "success")
                except Exception as e:
                    print_message(f"{EMOJI['error']} Invalid URL encoded string: {e}", "error")
            else:
                print_message(f"{EMOJI['warning']} Input cannot be empty.", "warning")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

def security_tools():
    """Provides basic security utilities."""
    print_header(f"{EMOJI['security']} Security Tools")

    while True:
        print(f"\n{COLOR['menu_option']}1. Generate MD5 Hash{COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. Generate SHA256 Hash{COLOR['reset']}")
        print(f"{COLOR['menu_option']}3. Generate Strong Password{COLOR['reset']}")
        print(f"{COLOR['menu_option']}4. Generate UUID{COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            text_to_hash = input(f"{COLOR['prompt']}{EMOJI['input']} Enter text to hash (MD5): {COLOR['reset']}").strip()
            if text_to_hash:
                md5_hash = hashlib.md5(text_to_hash.encode('utf-8')).hexdigest()
                print_message(f"\n{EMOJI['success']} MD5 Hash:\n{COLOR['output']}{md5_hash}{COLOR['reset']}", "success")
            else:
                print_message(f"{EMOJI['warning']} Input cannot be empty.", "warning")
        elif choice == '2':
            text_to_hash = input(f"{COLOR['prompt']}{EMOJI['input']} Enter text to hash (SHA256): {COLOR['reset']}").strip()
            if text_to_hash:
                sha256_hash = hashlib.sha256(text_to_hash.encode('utf-8')).hexdigest()
                print_message(f"\n{EMOJI['success']} SHA256 Hash:\n{COLOR['output']}{sha256_hash}{COLOR['reset']}", "success")
            else:
                print_message(f"{EMOJI['warning']} Input cannot be empty.", "warning")
        elif choice == '3':
            try:
                length = int(input(f"{COLOR['prompt']}{EMOJI['input']} Enter password length (e.g., 16): {COLOR['reset']}").strip())
                if length <= 0:
                    print_message(f"{EMOJI['warning']} Length must be a positive number.", "warning")
                    continue
                
                characters = string.ascii_letters + string.digits + string.punctuation
                password = ''.join(random.choice(characters) for i in range(length))
                print_message(f"\n{EMOJI['success']} Generated Password:\n{COLOR['output']}{password}{COLOR['reset']}", "success")
            except ValueError:
                print_message(f"{EMOJI['error']} Invalid length. Please enter a number.", "error")
        elif choice == '4':
            generated_uuid = str(uuid.uuid4())
            print_message(f"\n{EMOJI['success']} Generated UUID:\n{COLOR['output']}{generated_uuid}{COLOR['reset']}", "success")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

def ssl_utilities():
    """Provides SSL/TLS related utilities."""
    print_header(f"{EMOJI['ssl']} SSL/TLS Utilities")

    while True:
        print(f"\n{COLOR['menu_option']}1. View SSL Certificate Details (from file){COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. Check Website SSL Certificate (basic){COLOR['reset']}")
        print(f"{COLOR['menu_option']}3. Generate Self-Signed SSL Certificate (for testing){COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            cert_path = input(f"{COLOR['prompt']}{EMOJI['input']} Enter path to certificate file (e.g., cert.pem): {COLOR['reset']}").strip()
            if cert_path:
                if os.path.exists(cert_path):
                    cmd = f"openssl x509 -in {cert_path} -text -noout"
                    cert_details = run_command(cmd)
                    if cert_details:
                        print_message(f"\n{EMOJI['success']} Certificate Details for '{cert_path}':\n{COLOR['output']}{cert_details}{COLOR['reset']}", "success")
                    else:
                        print_message(f"{EMOJI['error']} Failed to get certificate details. Is OpenSSL installed and the file valid?", "error")
                else:
                    print_message(f"{EMOJI['warning']} Certificate file '{cert_path}' not found.", "warning")
            else:
                print_message(f"{EMOJI['warning']} Certificate file path cannot be empty.", "warning")
        elif choice == '2':
            host_port = input(f"{COLOR['prompt']}{EMOJI['input']} Enter host:port for SSL check (e.g., google.com:443): {COLOR['reset']}").strip()
            if host_port:
                cmd = f"openssl s_client -connect {host_port} -showcerts < /dev/null 2>/dev/null"
                # Using < /dev/null 2>/dev/null to prevent openssl from waiting for input and suppress stderr
                if platform.system() == "Windows":
                    cmd = f"echo | openssl s_client -connect {host_port} -showcerts 2>NUL"
                
                ssl_output = run_command(cmd)
                if ssl_output:
                    print_message(f"\n{EMOJI['success']} SSL Certificate Info for {host_port}:\n{COLOR['output']}{ssl_output}{COLOR['reset']}", "success")
                else:
                    print_message(f"{EMOJI['error']} Failed to connect or retrieve SSL certificate. Check host:port and OpenSSL installation.", "error")
            else:
                print_message(f"{EMOJI['warning']} Host:port cannot be empty.", "warning")
        elif choice == '3':
            common_name = input(f"{COLOR['prompt']}{EMOJI['input']} Enter Common Name (e.g., example.com): {COLOR['reset']}").strip()
            days = input(f"{COLOR['prompt']}{EMOJI['input']} Enter validity in days (e.g., 365): {COLOR['reset']}").strip()
            
            if common_name and days.isdigit():
                key_file = f"{common_name}.key"
                cert_file = f"{common_name}.crt"
                
                # Generate private key
                key_cmd = f"openssl genrsa -out {key_file} 2048"
                key_result = run_command(key_cmd)
                
                if key_result is not None:
                    print_message(f"{EMOJI['success']} Private key '{key_file}' generated.", "success")
                    # Generate self-signed certificate
                    cert_cmd = f"openssl req -x509 -new -nodes -key {key_file} -sha256 -days {days} -out {cert_file} -subj '/CN={common_name}'"
                    cert_result = run_command(cert_cmd)
                    
                    if cert_result is not None:
                        print_message(f"{EMOJI['success']} Self-signed certificate '{cert_file}' generated successfully.", "success")
                        print_message(f"{EMOJI['info']} Key: {key_file}, Cert: {cert_file}", "info")
                        print_message(f"{EMOJI['warning']} This is a self-signed certificate for TESTING ONLY and should NOT be used in production.", "warning")
                    else:
                        print_message(f"{EMOJI['error']} Failed to generate self-signed certificate.", "error")
                else:
                    print_message(f"{EMOJI['error']} Failed to generate private key.", "error")
            else:
                print_message(f"{EMOJI['warning']} Common Name and Days cannot be empty and days must be a number.", "warning")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

def _xor_cipher(data, key):
    """
    Performs a simple XOR operation for encryption/decryption.
    This is for demonstration/obfuscation ONLY, NOT for strong security.
    """
    key_len = len(key)
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % key_len]
    return result

def encryption_decryption_tools():
    """Provides basic encryption/decryption utilities (for demonstration)."""
    print_header(f"{EMOJI['encrypt']} Encryption/Decryption Tools (Basic)")
    print_message(f"{EMOJI['warning']} These tools use simple methods (e.g., XOR) and are for DEMONSTRATION/OBFUSCATION ONLY.", "warning")
    print_message(f"{EMOJI['warning']} They are NOT suitable for securing sensitive production data.", "warning")

    while True:
        print(f"\n{COLOR['menu_option']}1. Encrypt Text (Basic XOR){COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. Decrypt Text (Basic XOR){COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            plaintext = input(f"{COLOR['prompt']}{EMOJI['input']} Enter text to encrypt: {COLOR['reset']}").strip()
            passphrase = input(f"{COLOR['prompt']}{EMOJI['input']} Enter a passphrase (key): {COLOR['reset']}").strip()
            
            if plaintext and passphrase:
                encrypted_bytes = _xor_cipher(plaintext.encode('utf-8'), passphrase.encode('utf-8'))
                # Base64 encode the result to make it printable
                encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
                print_message(f"\n{EMOJI['success']} Encrypted (Base64 encoded):\n{COLOR['output']}{encrypted_b64}{COLOR['reset']}", "success")
            else:
                print_message(f"{EMOJI['warning']} Text and passphrase cannot be empty.", "warning")
        elif choice == '2':
            encrypted_b64 = input(f"{COLOR['prompt']}{EMOJI['input']} Enter Base64 encoded text to decrypt: {COLOR['reset']}").strip()
            passphrase = input(f"{COLOR['prompt']}{EMOJI['input']} Enter the passphrase (key): {COLOR['reset']}").strip()
            
            if encrypted_b64 and passphrase:
                try:
                    encrypted_bytes = base64.b64decode(encrypted_b64)
                    decrypted_bytes = _xor_cipher(encrypted_bytes, passphrase.encode('utf-8'))
                    decrypted_text = decrypted_bytes.decode('utf-8')
                    print_message(f"\n{EMOJI['success']} Decrypted Text:\n{COLOR['output']}{decrypted_text}{COLOR['reset']}", "success")
                except Exception as e:
                    print_message(f"{EMOJI['error']} Decryption failed. Check Base64 string and passphrase. Error: {e}", "error")
            else:
                print_message(f"{EMOJI['warning']} Encrypted text and passphrase cannot be empty.", "warning")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

def cloud_utilities():
    """Provides basic cloud (AWS/Azure/GCP) utilities - CLI presence checks and sample commands."""
    print_header(f"{EMOJI['cloud']} Cloud Utilities")
    print_message(f"{EMOJI['info']} This section provides basic checks for cloud CLIs and sample commands.", "info")
    print_message(f"{EMOJI['info']} Full functionality requires respective CLIs (aws, az, gcloud) to be installed and configured.", "info")

    while True:
        print(f"\n{COLOR['menu_option']}1. Check AWS CLI presence{COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. List AWS S3 buckets (requires AWS CLI configured){COLOR['reset']}")
        print(f"{COLOR['menu_option']}3. Check Azure CLI presence{COLOR['reset']}")
        print(f"{COLOR['menu_option']}4. List Azure Resource Groups (requires Azure CLI configured){COLOR['reset']}")
        print(f"{COLOR['menu_option']}5. Check GCP gcloud CLI presence{COLOR['reset']}")
        print(f"{COLOR['menu_option']}6. List GCP Projects (requires gcloud CLI configured){COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            aws_cli_path = run_command("which aws" if platform.system() != "Windows" else "where aws", check=False)
            if aws_cli_path:
                print_message(f"{EMOJI['success']} AWS CLI found at: {aws_cli_path}", "success")
            else:
                print_message(f"{EMOJI['error']} AWS CLI not found. Please install it.", "error")
        elif choice == '2':
            s3_buckets = run_command("aws s3 ls", check=False)
            if s3_buckets:
                print_message(f"\n{EMOJI['success']} AWS S3 Buckets:\n{COLOR['output']}{s3_buckets}{COLOR['reset']}", "success")
            else:
                print_message(f"{EMOJI['error']} Failed to list S3 buckets. Ensure AWS CLI is installed and configured with credentials.", "error")
        elif choice == '3':
            az_cli_path = run_command("which az" if platform.system() != "Windows" else "where az", check=False)
            if az_cli_path:
                print_message(f"{EMOJI['success']} Azure CLI found at: {az_cli_path}", "success")
            else:
                print_message(f"{EMOJI['error']} Azure CLI not found. Please install it.", "error")
        elif choice == '4':
            az_rgs = run_command("az group list --output tsv --query '[].name'", check=False)
            if az_rgs:
                print_message(f"\n{EMOJI['success']} Azure Resource Groups:\n{COLOR['output']}{az_rgs}{COLOR['reset']}", "success")
            else:
                print_message(f"{EMOJI['error']} Failed to list Azure Resource Groups. Ensure Azure CLI is installed and logged in.", "error")
        elif choice == '5':
            gcloud_cli_path = run_command("which gcloud" if platform.system() != "Windows" else "where gcloud", check=False)
            if gcloud_cli_path:
                print_message(f"{EMOJI['success']} GCP gcloud CLI found at: {gcloud_cli_path}", "success")
            else:
                print_message(f"{EMOJI['error']} GCP gcloud CLI not found. Please install it.", "error")
        elif choice == '6':
            gcloud_projects = run_command("gcloud projects list --format='value(projectId)'", check=False)
            if gcloud_projects:
                print_message(f"\n{EMOJI['success']} GCP Projects:\n{COLOR['output']}{gcloud_projects}{COLOR['reset']}", "success")
            else:
                print_message(f"{EMOJI['error']} Failed to list GCP Projects. Ensure gcloud CLI is installed and authenticated.", "error")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

def monitoring_logging_tools():
    """Provides basic monitoring and logging utilities."""
    print_header(f"{EMOJI['monitor']} Monitoring & Logging Tools")

    while True:
        print(f"\n{COLOR['menu_option']}1. View System Logs (tail -f /var/log/syslog or Windows Event Logs){COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. Check Service Status{COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            print_message(f"\n{EMOJI['info']} Viewing System Logs...", "info")
            if platform.system() in ["Linux", "Darwin"]:
                log_file = "/var/log/syslog" if platform.system() == "Linux" else "/var/log/system.log"
                if os.path.exists(log_file):
                    print_message(f"Tailing last 10 lines of {log_file}. Press Ctrl+C to stop.", "info")
                    run_command(f"tail -n 10 {log_file}", capture_output=False, check=False) # Direct output
                else:
                    print_message(f"{EMOJI['warning']} Log file '{log_file}' not found. Try checking other common log paths.", "warning")
            elif platform.system() == "Windows":
                print_message(f"Retrieving last 10 Windows Event Log entries (System).", "info")
                # Using PowerShell to get recent system events
                cmd = "powershell -command \"Get-WinEvent -LogName System -MaxEvents 10 | Format-List -Property TimeCreated, LevelDisplayName, Message\""
                event_logs = run_command(cmd)
                print(COLOR['output'] + (event_logs if event_logs else "Failed to retrieve Windows Event Logs.") + COLOR['reset'])
            else:
                print_message("System log viewing not supported on this OS.", "error")
            print_message(f"{EMOJI['success']} System log view completed.", "success")
        elif choice == '2':
            service_name = input(f"{COLOR['prompt']}{EMOJI['input']} Enter service name to check (e.g., apache2, sshd, Docker): {COLOR['reset']}").strip()
            if service_name:
                if platform.system() in ["Linux", "Darwin"]:
                    check_cmd = f"systemctl status {service_name}"
                elif platform.system() == "Windows":
                    check_cmd = f"sc query {service_name}"
                else:
                    print_message("Service status checking not supported on this OS.", "error")
                    continue
                
                service_status = run_command(check_cmd, check=False) # Don't check=True as non-zero exit is common for stopped services
                if service_status:
                    print_message(f"\n{EMOJI['success']} Status for '{service_name}':\n{COLOR['output']}{service_status}{COLOR['reset']}", "success")
                else:
                    print_message(f"{EMOJI['error']} Failed to retrieve status for '{service_name}'. Service might not exist or command failed.", "error")
            else:
                print_message(f"{EMOJI['warning']} Service name cannot be empty.", "warning")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

def package_management_tools():
    """Provides basic package management utilities."""
    print_header(f"{EMOJI['package']} Package Management Tools")
    print_message(f"{EMOJI['info']} This section uses common package managers (apt, yum, brew, choco).", "info")
    print_message(f"{EMOJI['info']} Ensure the relevant package manager is installed and configured for your OS.", "info")

    while True:
        print(f"\n{COLOR['menu_option']}1. Update Package Lists{COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. Install a Package{COLOR['reset']}")
        print(f"{COLOR['menu_option']}3. Remove a Package{COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            print_message(f"\n{EMOJI['loading']} Updating package lists...", "info")
            if platform.system() == "Linux":
                if run_command("which apt", check=False):
                    update_cmd = "sudo apt update"
                elif run_command("which yum", check=False):
                    update_cmd = "sudo yum check-update"
                else:
                    print_message(f"{EMOJI['error']} No common Linux package manager (apt/yum) found.", "error")
                    continue
            elif platform.system() == "Darwin":
                update_cmd = "brew update"
            elif platform.system() == "Windows":
                update_cmd = "choco upgrade all -y --no-progress" # Upgrade all installed packages
            else:
                print_message("Package list update not supported on this OS.", "error")
                continue
            
            update_result = run_command(update_cmd)
            if update_result is not None:
                print(COLOR['output'] + update_result + COLOR['reset'])
                print_message(f"{EMOJI['success']} Package lists updated successfully.", "success")
            else:
                print_message(f"{EMOJI['error']} Failed to update package lists.", "error")
        elif choice == '2':
            package_name = input(f"{COLOR['prompt']}{EMOJI['input']} Enter package name to install: {COLOR['reset']}").strip()
            if package_name:
                print_message(f"\n{EMOJI['loading']} Installing package '{package_name}'...", "info")
                if platform.system() == "Linux":
                    if run_command("which apt", check=False):
                        install_cmd = f"sudo apt install -y {package_name}"
                    elif run_command("which yum", check=False):
                        install_cmd = f"sudo yum install -y {package_name}"
                    else:
                        print_message(f"{EMOJI['error']} No common Linux package manager (apt/yum) found.", "error")
                        continue
                elif platform.system() == "Darwin":
                    install_cmd = f"brew install {package_name}"
                elif platform.system() == "Windows":
                    install_cmd = f"choco install {package_name} -y --no-progress"
                else:
                    print_message("Package installation not supported on this OS.", "error")
                    continue
                
                install_result = run_command(install_cmd)
                if install_result is not None:
                    print(COLOR['output'] + install_result + COLOR['reset'])
                    print_message(f"{EMOJI['success']} Package '{package_name}' installed successfully.", "success")
                else:
                    print_message(f"{EMOJI['error']} Failed to install package '{package_name}'.", "error")
            else:
                print_message(f"{EMOJI['warning']} Package name cannot be empty.", "warning")
        elif choice == '3':
            package_name = input(f"{COLOR['prompt']}{EMOJI['input']} Enter package name to remove: {COLOR['reset']}").strip()
            if package_name:
                print_message(f"\n{EMOJI['loading']} Removing package '{package_name}'...", "info")
                if platform.system() == "Linux":
                    if run_command("which apt", check=False):
                        remove_cmd = f"sudo apt remove -y {package_name}"
                    elif run_command("which yum", check=False):
                        remove_cmd = f"sudo yum remove -y {package_name}"
                    else:
                        print_message(f"{EMOJI['error']} No common Linux package manager (apt/yum) found.", "error")
                        continue
                elif platform.system() == "Darwin":
                    remove_cmd = f"brew uninstall {package_name}"
                elif platform.system() == "Windows":
                    remove_cmd = f"choco uninstall {package_name} -y --no-progress"
                else:
                    print_message("Package removal not supported on this OS.", "error")
                    continue
                
                remove_result = run_command(remove_cmd)
                if remove_result is not None:
                    print(COLOR['output'] + remove_result + COLOR['reset'])
                    print_message(f"{EMOJI['success']} Package '{package_name}' removed successfully.", "success")
                else:
                    print_message(f"{EMOJI['error']} Failed to remove package '{package_name}'.", "error")
            else:
                print_message(f"{EMOJI['warning']} Package name cannot be empty.", "warning")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

def configuration_management_tools():
    """Provides basic configuration management utilities."""
    print_header(f"{EMOJI['config']} Configuration Management Tools")

    while True:
        print(f"\n{COLOR['menu_option']}1. View All Environment Variables{COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. Get Specific Environment Variable Value{COLOR['reset']}")
        print(f"{COLOR['menu_option']}3. Set Temporary Environment Variable (current session){COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            print_message(f"\n{EMOJI['info']} All Environment Variables:", "info")
            for key, value in os.environ.items():
                print(f"{COLOR['output']}{key}={value}{COLOR['reset']}")
            print_message(f"{EMOJI['success']} Environment variables displayed.", "success")
        elif choice == '2':
            var_name = input(f"{COLOR['prompt']}{EMOJI['input']} Enter environment variable name: {COLOR['reset']}").strip()
            if var_name:
                value = os.getenv(var_name)
                if value is not None:
                    print_message(f"\n{EMOJI['success']} Value of '{var_name}':\n{COLOR['output']}{value}{COLOR['reset']}", "success")
                else:
                    print_message(f"{EMOJI['warning']} Environment variable '{var_name}' not found.", "warning")
            else:
                print_message(f"{EMOJI['warning']} Variable name cannot be empty.", "warning")
        elif choice == '3':
            var_name = input(f"{COLOR['prompt']}{EMOJI['input']} Enter variable name to set: {COLOR['reset']}").strip()
            var_value = input(f"{COLOR['prompt']}{EMOJI['input']} Enter value for '{var_name}': {COLOR['reset']}").strip()
            if var_name:
                os.environ[var_name] = var_value
                print_message(f"{EMOJI['success']} Environment variable '{var_name}' set to '{var_value}' for this session.", "success")
                print_message(f"{EMOJI['info']} Note: This change is temporary and only affects the current terminal session.", "info")
            else:
                print_message(f"{EMOJI['warning']} Variable name cannot be empty.", "warning")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

def automation_scheduling_tools():
    """Provides basic automation and scheduling utilities."""
    print_header(f"{EMOJI['automation']} Automation & Scheduling Tools")

    while True:
        print(f"\n{COLOR['menu_option']}1. List Scheduled Tasks (Cron/Windows Scheduler){COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. Execute a Custom Shell Command/Script{COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            print_message(f"\n{EMOJI['info']} Listing Scheduled Tasks...", "info")
            if platform.system() in ["Linux", "Darwin"]:
                # Attempt to read user's crontab
                cron_output = run_command("crontab -l", check=False)
                if cron_output:
                    print_message(f"\n{EMOJI['success']} User's Cron Jobs:\n{COLOR['output']}{cron_output}{COLOR['reset']}", "success")
                else:
                    print_message(f"{EMOJI['warning']} No user cron jobs found or crontab not accessible.", "warning")
                
                # Also check system-wide cron jobs (common paths)
                print_message(f"\n{EMOJI['info']} Checking common system cron directories...", "info")
                system_cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly"]
                found_system_cron = False
                for cron_dir in system_cron_dirs:
                    if os.path.exists(cron_dir):
                        dir_content = run_command(f"ls -l {cron_dir}", check=False)
                        if dir_content:
                            print_message(f"Content of {cron_dir}:\n{COLOR['output']}{dir_content}{COLOR['reset']}", "info")
                            found_system_cron = True
                if not found_system_cron:
                    print_message(f"{EMOJI['warning']} No system cron jobs found in common directories.", "warning")

            elif platform.system() == "Windows":
                # Using schtasks to list scheduled tasks
                cmd = "powershell -command \"schtasks /query /fo LIST /v\""
                scheduled_tasks = run_command(cmd)
                print(COLOR['output'] + (scheduled_tasks if scheduled_tasks else "Failed to retrieve Windows Scheduled Tasks.") + COLOR['reset'])
            else:
                print_message("Scheduled task listing not supported on this OS.", "error")
            print_message(f"{EMOJI['success']} Scheduled tasks listed.", "success")
        elif choice == '2':
            command_to_execute = input(f"{COLOR['prompt']}{EMOJI['input']} Enter shell command or path to script to execute: {COLOR['reset']}").strip()
            if command_to_execute:
                print_message(f"\n{EMOJI['loading']} Executing custom command...", "info")
                custom_output = run_command(command_to_execute)
                if custom_output is not None:
                    print_message(f"\n{EMOJI['success']} Command executed successfully. Output:\n{COLOR['output']}{custom_output}{COLOR['reset']}", "success")
                else:
                    print_message(f"{EMOJI['error']} Custom command execution failed.", "error")
            else:
                print_message(f"{EMOJI['warning']} Command cannot be empty.", "warning")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

def development_utilities():
    """Provides basic development-related utilities."""
    print_header(f"{EMOJI['dev']} Development Utilities")

    while True:
        print(f"\n{COLOR['menu_option']}1. Check Python Version{COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. Check Node.js Version{COLOR['reset']}")
        print(f"{COLOR['menu_option']}3. Check Java Version{COLOR['reset']}")
        print(f"{COLOR['menu_option']}4. Run npm install (in current directory){COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            python_version = run_command("python --version" if platform.system() != "Windows" else "python -V", check=False)
            if python_version:
                print_message(f"{EMOJI['success']} Python Version: {COLOR['output']}{python_version}{COLOR['reset']}", "success")
            else:
                print_message(f"{EMOJI['error']} Python not found or command failed.", "error")
        elif choice == '2':
            node_version = run_command("node -v", check=False)
            if node_version:
                print_message(f"{EMOJI['success']} Node.js Version: {COLOR['output']}{node_version}{COLOR['reset']}", "success")
            else:
                print_message(f"{EMOJI['error']} Node.js not found or command failed.", "error")
        elif choice == '3':
            java_version = run_command("java -version", check=False)
            if java_version:
                print_message(f"{EMOJI['success']} Java Version:\n{COLOR['output']}{java_version}{COLOR['reset']}", "success")
            else:
                print_message(f"{EMOJI['error']} Java not found or command failed.", "error")
        elif choice == '4':
            print_message(f"\n{EMOJI['loading']} Running 'npm install' in current directory...", "info")
            npm_install_result = run_command("npm install", check=False)
            if npm_install_result is not None:
                print_message(f"{EMOJI['success']} npm install completed. Output:\n{COLOR['output']}{npm_install_result}{COLOR['reset']}", "success")
            else:
                print_message(f"{EMOJI['error']} npm install failed. Check if Node.js and npm are installed, and if package.json exists.", "error")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

def windows_specific_tools():
    """Provides Windows-specific system and administration utilities."""
    if platform.system() != "Windows":
        print_message(f"{EMOJI['error']} This category is for Windows systems only. Your OS is {platform.system()}.", "error")
        return

    print_header(f"{EMOJI['windows']} Windows Specific Tools")

    while True:
        print(f"\n{COLOR['menu_option']}1. List Windows Services{COLOR['reset']}")
        print(f"{COLOR['menu_option']}2. Start a Windows Service{COLOR['reset']}")
        print(f"{COLOR['menu_option']}3. Stop a Windows Service{COLOR['reset']}")
        print(f"{COLOR['menu_option']}4. View Network Adapters (PowerShell){COLOR['reset']}")
        print(f"{COLOR['menu_option']}5. List Local Users{COLOR['reset']}")
        print(f"{COLOR['menu_option']}b. Back to Main Menu{COLOR['reset']}")

        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip().lower()

        if choice == '1':
            print_message(f"\n{EMOJI['info']} Listing Windows Services (Get-Service):", "info")
            services = run_command("powershell -command \"Get-Service | Format-Table Name, Status -AutoSize\"")
            print(COLOR['output'] + (services if services else "Failed to list Windows services.") + COLOR['reset'])
            print_message(f"{EMOJI['success']} Windows services displayed.", "success")
        elif choice == '2':
            service_name = input(f"{COLOR['prompt']}{EMOJI['input']} Enter service name to START: {COLOR['reset']}").strip()
            if service_name:
                start_result = run_command(f"powershell -command \"Start-Service -Name '{service_name}' -PassThru\"")
                if start_result is not None:
                    print_message(f"{EMOJI['success']} Service '{service_name}' started successfully.", "success")
                    print(COLOR['output'] + start_result + COLOR['reset'])
                else:
                    print_message(f"{EMOJI['error']} Failed to start service '{service_name}'. Check service name and permissions.", "error")
            else:
                print_message(f"{EMOJI['warning']} Service name cannot be empty.", "warning")
        elif choice == '3':
            service_name = input(f"{COLOR['prompt']}{EMOJI['input']} Enter service name to STOP: {COLOR['reset']}").strip()
            if service_name:
                stop_result = run_command(f"powershell -command \"Stop-Service -Name '{service_name}' -PassThru\"")
                if stop_result is not None:
                    print_message(f"{EMOJI['success']} Service '{service_name}' stopped successfully.", "success")
                    print(COLOR['output'] + stop_result + COLOR['reset'])
                else:
                    print_message(f"{EMOJI['error']} Failed to stop service '{service_name}'. Check service name and permissions.", "error")
            else:
                print_message(f"{EMOJI['warning']} Service name cannot be empty.", "warning")
        elif choice == '4':
            print_message(f"\n{EMOJI['info']} Viewing Network Adapters (Get-NetAdapter):", "info")
            net_adapters = run_command("powershell -command \"Get-NetAdapter | Format-Table Name, Status, MacAddress, LinkSpeed -AutoSize\"")
            print(COLOR['output'] + (net_adapters if net_adapters else "Failed to retrieve network adapters.") + COLOR['reset'])
            print_message(f"{EMOJI['success']} Network adapters displayed.", "success")
        elif choice == '5':
            print_message(f"\n{EMOJI['info']} Listing Local Users (net user):", "info")
            local_users = run_command("net user")
            print(COLOR['output'] + (local_users if local_users else "Failed to list local users.") + COLOR['reset'])
            print_message(f"{EMOJI['success']} Local users displayed.", "success")
        elif choice == 'b':
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please try again.", "warning")

# --- Main Application Logic ---

def display_main_menu():
    """Displays the main menu options."""
    print_header(f"{EMOJI['menu']} Main Menu")
    print(f"{COLOR['menu_option']}1. {EMOJI['system']} System Information{COLOR['reset']}")
    print(f"{COLOR['menu_option']}2. {EMOJI['process']} Process Management{COLOR['reset']}")
    print(f"{COLOR['menu_option']}3. {EMOJI['network']} Network Utilities{COLOR['reset']}")
    print(f"{COLOR['menu_option']}4. {EMOJI['file']} File Operations{COLOR['reset']}")
    print(f"{COLOR['menu_option']}5. {EMOJI['container']} Container Utilities (Docker){COLOR['reset']}")
    print(f"{COLOR['menu_option']}6. {EMOJI['git']} Git Utilities{COLOR['reset']}")
    print(f"{COLOR['menu_option']}7. {EMOJI['text']} Text Processing Tools{COLOR['reset']}")
    print(f"{COLOR['menu_option']}8. {EMOJI['security']} Security Tools{COLOR['reset']}")
    print(f"{COLOR['menu_option']}9. {EMOJI['ssl']} SSL/TLS Utilities{COLOR['reset']}")
    print(f"{COLOR['menu_option']}10. {EMOJI['encrypt']} Encryption/Decryption Tools{COLOR['reset']}")
    print(f"{COLOR['menu_option']}11. {EMOJI['cloud']} Cloud Utilities (Basic CLI){COLOR['reset']}")
    print(f"{COLOR['menu_option']}12. {EMOJI['monitor']} Monitoring & Logging Tools{COLOR['reset']}")
    print(f"{COLOR['menu_option']}13. {EMOJI['package']} Package Management Tools{COLOR['reset']}")
    print(f"{COLOR['menu_option']}14. {EMOJI['config']} Configuration Management Tools{COLOR['reset']}")
    print(f"{COLOR['menu_option']}15. {EMOJI['automation']} Automation & Scheduling Tools{COLOR['reset']}") # New Category
    print(f"{COLOR['menu_option']}16. {EMOJI['dev']} Development Utilities{COLOR['reset']}") # New Category
    print(f"{COLOR['menu_option']}17. {EMOJI['windows']} Windows Specific Tools{COLOR['reset']}") # New Category
    print(f"{COLOR['menu_option']}18. {EMOJI['exit']} Exit{COLOR['reset']}") # Updated Exit option
    print(f"{COLOR['header']}{EMOJI['separator'] * 3}{COLOR['reset']}")

def main():
    """Main function to run the DevOps Swiss Army Knife."""
    print(f"{COLOR['header']}{EMOJI['separator']} Welcome to {APP_NAME} v{VERSION} {EMOJI['separator']}{COLOR['reset']}")
    print_message(f"Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "info")

    while True:
        display_main_menu()
        choice = input(f"{COLOR['prompt']}{EMOJI['input']} Enter your choice: {COLOR['reset']}").strip()

        if choice == '1':
            display_system_info()
        elif choice == '2':
            manage_processes()
        elif choice == '3':
            network_utilities()
        elif choice == '4':
            file_operations()
        elif choice == '5':
            container_utilities()
        elif choice == '6':
            git_utilities()
        elif choice == '7':
            text_processing_tools()
        elif choice == '8':
            security_tools()
        elif choice == '9':
            ssl_utilities()
        elif choice == '10':
            encryption_decryption_tools()
        elif choice == '11':
            cloud_utilities()
        elif choice == '12':
            monitoring_logging_tools()
        elif choice == '13':
            package_management_tools()
        elif choice == '14':
            configuration_management_tools()
        elif choice == '15': # New option number
            automation_scheduling_tools()
        elif choice == '16': # New option number
            development_utilities()
        elif choice == '17': # New option number
            windows_specific_tools()
        elif choice == '18': # Updated Exit option number
            print_message(f"{EMOJI['exit']} Exiting {APP_NAME}. Goodbye! {EMOJI['exit']}", "info")
            break
        else:
            print_message(f"{EMOJI['warning']} Invalid choice. Please select a valid option from the menu.", "warning")
        
        # Pause before showing menu again, unless exiting
        if choice != '18': # Updated Exit option number
            input(f"{COLOR['prompt']}{EMOJI['input']} Press Enter to continue...{COLOR['reset']}")
            os.system('cls' if os.name == 'nt' else 'clear') # Clear screen for better readability

if __name__ == "__main__":
    main()