# ⚡ Vult

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-blue)](https://github.com)
[![Shell](https://img.shields.io/badge/Shell-Bash%20%7C%20PowerShell-green)](https://github.com)

Simple wrapper for running 30+ security & vulnerability scanning tools locally or on remote systems via SSH.


## 📚 Table of Contents

[✨ Features](#-features) • [📋 Requirements](#-requirements) •
[🛠️ Installation](#️-installation) • [📖 Usage](#-usage) •
[🔧 Common Commands](#-common-commands) • [⚙️ Configuration](#️-configuration) •
[🏗️ Architecture](#️-architecture) • [📁 Project Structure](#-project-structure) •
[🔧 Troubleshooting](#-troubleshooting) • [🔒 Security Considerations](#-security-considerations) •
[🤝 Contributing](#-contributing) • [📝 License](#-license) •
[💜 Support Development](#-support-development) • [⚠️ Disclaimer](#️-disclaimer)

</div>


## ✨ Features

- **30+ Security Tools**: Comprehensive collection of network, web, vulnerability, and forensics tools
- **Local & Remote Execution**: Run tools locally (`--local`) or on remote pentest boxes via SSH
- **Network Namespace Isolation**: Isolates tools to specific network interfaces
- **SSH Connection Protection**: Automatically prevents interface isolation that would disconnect your SSH session
- **Auto Dependency Management**: Installs missing tools automatically
- **Cross-Platform**: Bash (Linux) and PowerShell (Windows) versions
- **Log Management**: Keeps last 50 scan logs, auto-cleanup

## 📋 Requirements

- **Linux**: Kali Linux or Ubuntu with sudo access
- **Windows**: PowerShell 5.1+ with SSH client
- **Remote**: SSH key access to pentest environment

## 🛠️ Installation

```bash
git clone <repository>
cd vult
chmod +x vult.sh
```

## 📖 Usage

### Basic Syntax

#### Bash (Local Execution on Kali/Pentest Systems)
```bash
./vult.sh --local --tool <tool> [--target <target>] [--iface <interface>]
```

#### Bash (Remote Execution via SSH)
```bash
./vult.sh --tool <tool> [--target <target>] [--iface <interface>] [--ssh-host <host>] [--ssh-user <user>] [--ssh-key <path>]
```

#### PowerShell (Always Remote via SSH)
```powershell
.\vult.ps1 -Tool <tool> [-Target <target>] [-Iface <interface>] [-SshHost <host>] [-SshUser <user>] [-SshKey <path>]
```

### Execution Modes

**🖥️ Local Execution (use --local flag)**
```bash
# Run directly on Kali/pentest systems
./vult.sh --local --tool nikto --target https://example.com
./vult.sh --local --tool quick-discovery --target 10.0.1.0/24 --iface eth0
```

**📡 Remote Execution (default)**
```bash
# Run via SSH from any system
./vult.sh --tool nikto --target https://example.com --ssh-host kali-box
./vult.sh --tool quick-discovery --target 10.0.1.0/24 --iface eth0
```

### Available Tools

**Network Discovery & Port Scanning:**
- `quick-discovery` - Fast network discovery (nmap -sn)
- `full-tcp` - Full TCP port scan with service detection
- `specific-ports` - Scan specific ports
- `udp-scan` - UDP port scanning
- `custom-nmap` - Custom nmap commands
- `masscan` - High-speed port scanner
- `rustscan` - Fast port scanner
- `zmap` - Internet-wide scanning

**Web Application Security:**
- `nikto` - Web vulnerability scanner
- `gobuster` - Directory/file brute-forcer
- `ffuf` - Fast web fuzzer
- `whatweb` - Web technology fingerprinting
- `wafw00f` - Web Application Firewall detection
- `dirb` - Directory brute-forcer

**Vulnerability Scanning:**
- `nuclei` - Fast vulnerability scanner
- `sqlmap` - SQL injection testing
- `wpscan` - WordPress security scanner

**SSL/TLS Security:**
- `sslscan` - SSL/TLS configuration scanner
- `testssl` - Comprehensive SSL/TLS testing
- `sslyze` - SSL/TLS analyzer

**Service Enumeration:**
- `enum4linux` - SMB/NetBIOS enumeration
- `smbclient` - SMB client connections
- `ldapsearch` - LDAP enumeration
- `snmpwalk` - SNMP enumeration

**Exploitation & Research:**
- `searchsploit` - Exploit database search
- `msfconsole` - Metasploit framework

**Wireless Security:**
- `aircrack` - WiFi password cracking
- `wifite` - Automated wireless attacks

**Forensics & File Analysis:**
- `binwalk` - Firmware analysis tool
- `strings` - Extract strings from files
- `file-analysis` - Basic file analysis

**Utility:**
- `show-versions` - Display all tool versions

### Common Usage Examples

#### Network Discovery
```bash
# Quick network discovery (local execution)
./vult.sh --local --tool quick-discovery --target 10.0.1.0/24 --iface eth0

# Quick network discovery (remote execution)
./vult.sh --tool quick-discovery --target 10.0.1.0/24 --iface eth0 --ssh-host kali-box

# Full TCP port scan
./vult.sh --tool full-tcp --target 10.0.1.100 --iface eth1

# Specific ports with masscan
./vult.sh --tool masscan --target 10.0.1.0/24 --ports 80,443,22,3389
```

#### Web Application Testing
```bash
# Nikto web vulnerability scan (local mode)
./vult.sh --local --tool nikto --target https://example.com

# Directory brute-forcing
./vult.sh --tool gobuster --target https://example.com --args "dir -w /usr/share/wordlists/dirb/common.txt"

# Nuclei vulnerability scanning
./vult.sh --tool nuclei --target https://example.com --args "-t cves/"
```

#### SSL/TLS Assessment
```bash
# SSL configuration analysis
./vult.sh --tool sslscan --target example.com:443

# Comprehensive SSL testing
./vult.sh --tool testssl --target https://example.com
```

#### SSH Remote Execution
```bash
# Use specific SSH connection
./vult.sh --tool nmap --target 192.168.1.0/24 \
    --ssh-host pentest.example.com \
    --ssh-user admin \
    --ssh-key ~/.ssh/pentest_key

# PowerShell equivalent
.\vult.ps1 -Tool nmap -Target 192.168.1.0/24 `
    -SshHost pentest.example.com `
    -SshUser admin `
    -SshKey "C:\keys\pentest_key"
```

### Advanced Features

#### Debug Mode
```bash
# Enable debug output
./vult.sh --tool nmap --target 10.0.1.100 --debug
.\vult.ps1 -Tool nmap -Target 10.0.1.100 -DebugMode
```

#### Namespace Cleanup
```bash
# Clean up orphaned namespaces
./vult.sh --cleanup-namespaces
.\vult.ps1 -CleanupNamespaces
```

#### Custom Commands
```bash
# Custom nmap command
./vult.sh --tool custom-nmap --args "-sS -A -T4 10.0.1.100" --iface eth0

# Custom tool execution
./vult.sh --tool gobuster --target https://example.com --args "dir -w /custom/wordlist.txt -x php,html"
```

### Options
- `--local` - Run locally (default: remote via SSH)
- `--tool <name>` - Security tool to run
- `--target <target>` - Target IP/URL/network
- `--iface <interface>` - Network interface for isolation
- `--force-interface` - Force interface isolation even if it might disconnect SSH
- `--args "<args>"` - Custom tool arguments
- `--ssh-host <host>` - Remote SSH host
- `--ssh-user <user>` - SSH username
- `--ssh-key <path>` - SSH private key path

## 🔧 Common Commands

```bash
# Show all available tools
./vult.sh --tool show-versions

# Cleanup network namespaces
./vult.sh --cleanup-namespaces

# Get help
./vult.sh --help
```



### Quick Setup
```bash
# Clone or download the project
git clone <repository-url>
cd vult

# Make bash script executable
chmod +x vult.sh

# Verify scripts
./vult.sh --help
powershell -ExecutionPolicy Bypass -File "./vult.ps1" -Help
```

### Automatic Dependency Management
**No manual setup required!** 🎉

Vult automatically:
- **Detects missing tools** when you run any scan
- **Installs dependencies** automatically via package manager (apt/yum/pacman)
- **Downloads binaries** for tools not available in repositories
- **Handles special cases** like nuclei, rustscan, ffuf, gobuster from GitHub releases

Simply run any tool and Vult will ensure all dependencies are available before execution.

### SSH Key Setup
```bash
# Generate SSH key pair (if needed)
ssh-keygen -t rsa -b 4096 -f ~/.ssh/pentest_key

# Copy public key to remote server
ssh-copy-id -i ~/.ssh/pentest_key.pub user@remote-server

# Set appropriate permissions
chmod 600 ~/.ssh/pentest_key
```

<br>


## ⚙️ Configuration

### Environment Variables
Set these environment variables for default SSH connection parameters:

#### Linux/Bash
```bash
export REMOTE_HOST="your.pentest.server"
export REMOTE_USER="kali"
export SSH_KEY="/path/to/your/ssh/key"
```

#### Windows/PowerShell
```powershell
$env:REMOTE_HOST = "your.pentest.server"
$env:REMOTE_USER = "kali"
$env:SSH_KEY = "C:\path\to\your\ssh\key"
```

### SSH Configuration
Add to `~/.ssh/config` for easier connection management:
```
Host pentest-box
    HostName your.pentest.server
    User kali
    IdentityFile ~/.ssh/pentest_key
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
```

<br>


## 🏗️ Architecture

### Dual Execution Mode
Vult provides flexible execution options to suit different environments:

1. **Local Mode**: Direct execution on pentest systems with `--local` flag
2. **Remote Mode**: SSH-based execution from any system to pentest boxes (default)
3. **Full Feature Parity**: Identical commands and options regardless of execution mode
4. **Namespace Support**: Full network namespace isolation in both execution modes
5. **Unified Interface**: Same tool definitions and parameter handling across modes

### Automatic Dependency Management
Vult features intelligent dependency resolution that runs before every tool execution:

1. **Tool Analysis**: Identifies required packages based on the selected tool
2. **Availability Check**: Tests if commands are available on the target system (local or remote)
3. **Smart Installation**: Uses appropriate package manager (apt/yum/pacman) or direct downloads
4. **Special Handling**: Manages tools not in standard repositories (nuclei, rustscan, ffuf, gobuster)
5. **Caching**: Skips installation if tools are already available

### Network Namespace Isolation
Vult automatically creates isolated network namespaces for each tool execution:

1. **Interface Capture**: Temporarily moves the specified interface to an isolated namespace
2. **State Preservation**: Saves complete interface configuration (IP, broadcast, scope, routes)
3. **Tool Execution**: Runs the security tool within the isolated environment
4. **Automatic Restoration**: Restores interface to original state with all attributes
5. **Cleanup**: Removes temporary namespaces and routing rules

### Cross-Platform Design
- **Bash Version**: 
  - **Local Mode**: Native Linux execution with full namespace support (use `--local` flag)
  - **Remote Mode**: SSH-based remote execution from any system (default)
  - **Manual Control**: Explicit mode selection with `--local` parameter
- **PowerShell Version**: SSH-based remote execution with identical parameter handling and dependency management
- **Feature Parity**: Both versions support the same tools, options, and automatic dependency installation
- **Unified Logging**: Consistent log format and cleanup across platforms and execution modes

<br>


## 📁 Project Structure

```
vult/
├── README.md              # This comprehensive guide
├── vult.sh                # Bash version (Linux/native) with auto-dependency management
├── vult.ps1               # PowerShell version (Windows/remote) with auto-dependency management
└── logs/                  # Automatic scan logs (auto-cleanup)
    ├── scan_20240913-120000_nmap.log
    ├── scan_20240913-120500_nikto.log
    └── ... (latest 50 logs kept)
```

<br>


## 🔧 Troubleshooting

### Common Issues

#### SSH Connection Problems
```bash
# Test SSH connectivity
ssh -i /path/to/key user@host "echo 'Connection successful'"

# Debug SSH issues
./vult.sh --tool show-versions --debug
```

#### Permission Issues
```bash
# Ensure proper SSH key permissions
chmod 600 ~/.ssh/your_key

# Verify sudo access on remote server
ssh user@host "sudo -l"
```

#### Network Namespace Issues
```bash
# Check for orphaned namespaces
sudo ip netns list

# Clean up manually
./vult.sh --cleanup-namespaces
```

#### Tool Not Found
```bash
# Verify tool installation on remote server
ssh user@host "which nmap"

# Install missing tools
ssh user@host "sudo apt install nmap"
```

### Log Analysis
```bash
# View recent logs
ls -la logs/ | tail -10

# Search for specific scan results
grep -r "open" logs/

# Monitor real-time execution
tail -f logs/scan_$(date +%Y%m%d)*.log
```

<br>


## 🔒 Security Considerations

### SSH Connection Protection
- **Automatic Detection**: Vult automatically detects when you're connected via SSH
- **Interface Protection**: Prevents isolating network interfaces used by your SSH connection
- **Safe Fallback**: Commands run without namespace isolation if SSH interface is detected
- **Override Option**: Use `--force-interface` flag to override protection (may disconnect SSH)
- **Multi-Interface Support**: Works safely with multiple network interfaces

### Best Practices
- **SSH Key Security**: Use dedicated SSH keys with strong passphrases
- **Network Segmentation**: Execute from isolated networks when possible
- **Log Management**: Regularly review and securely store scan logs
- **Access Control**: Limit SSH access to pentest-specific accounts
- **Scope Management**: Always verify target scope before execution

### Operational Security
- **Legal Authorization**: Ensure proper authorization before scanning
- **Target Validation**: Verify target networks and IP ranges
- **Rate Limiting**: Use appropriate timing and rate controls
- **Log Retention**: Follow organizational data retention policies

<br>


## 🤝 Contributing

### Development Setup
```bash
# Fork the repository
git clone <your-fork>
cd vult

# Create feature branch
git checkout -b feature/your-feature

# Test changes
./vult.sh --tool show-versions
.\vult.ps1 -Tool show-versions

# Submit pull request
```

### Adding New Tools
1. Add tool definition to both `vult.sh` and `vult.ps1`
2. Include usage examples in help text
3. Test with various parameter combinations
4. Update README.md with new tool information

<br>


## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

<br>


## 💜 Support Development

If you find this Project useful, please consider supporting this and future work, which highly relies on Coffee:

<div align="center">
<a href="https://www.buymeacoffee.com/itbaer" target="_blank"><img src="https://github.com/user-attachments/assets/64107f03-ba5b-473e-b8ad-f3696fe06002" alt="Buy Me A Coffee" style="height: 60px; max-width: 217px;"></a>
<br>
<a href="https://www.paypal.com/donate/?hosted_button_id=5XXRC7THMTRRS" target="_blank">Donate via PayPal</a>
</div>

<br>

## ⚠️ Disclaimer

This tool is intended for authorized vulnerability scanning and security research only. Users are responsible for ensuring they have proper authorization before conducting any security testing. The authors are not responsible for any misuse or damage caused by this tool.

