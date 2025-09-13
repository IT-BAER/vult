# Pentest Launcher (PowerShell) - Remote Execution
param(
    [string]$Tool = "",
    [string]$Target = "",
    [string]$Iface = "",
    [string]$Ports = "",
    [string]$CustomArgs = "",
    [string]$SshHost = "",
    [string]$SshUser = "",
    [string]$SshKey = "",
    [switch]$DebugMode,
    [switch]$CleanupNamespaces
)

# ---- Configuration ----
$REMOTE_HOST = if ($SshHost) { $SshHost } elseif ($env:REMOTE_HOST) { $env:REMOTE_HOST } else { "12.34.56.78" }
$REMOTE_USER = if ($SshUser) { $SshUser } elseif ($env:REMOTE_USER) { $env:REMOTE_USER } else { "kali" }
$SSH_KEY = if ($SshKey) { $SshKey } elseif ($env:SSH_KEY) { $env:SSH_KEY } else { "C:\Users\user.name\.ssh\kali" }

# ---- Usage Function ----
function Show-Usage {
    Write-Host @"
Vult (PowerShell) - All-in-One Vulnerability Scanner
Usage:
  .\vult.ps1 -Tool <tool> [-Target <target>] [-Iface <iface>] [-Ports <ports>] [-CustomArgs "<custom_args>"] [-SshHost <host>] [-SshUser <user>] [-SshKey <path>]

SSH Connection Options:
  -SshHost <host>         SSH host/IP address (default: 12.34.56.78 or `$env:REMOTE_HOST)
  -SshUser <user>         SSH username (default: kali or `$env:REMOTE_USER)
  -SshKey <path>          SSH private key path (default: C:\Users\user.name\.ssh\kali or `$env:SSH_KEY)

Other Options:
  -DebugMode              Enable debug output showing SSH connection details
  -CleanupNamespaces      Clean up orphaned network namespaces

Note: Log files are automatically cleaned up to keep only the latest 50 scan logs.

Available Tools:
  # Network Discovery & Port Scanning
  -Tool quick-discovery   -Target <cidr>         [-Iface <iface>]
  -Tool full-tcp         -Target <targets>       [-Iface <iface>]
  -Tool specific-ports   -Target <target> -Ports <ports> [-Iface <iface>]
  -Tool udp-scan         -Target <target>        [-Iface <iface>]
  -Tool masscan          -Target <target> -Ports <ports> [-CustomArgs "<args>"]
  -Tool rustscan         -Target <target>        [-Ports <ports>]
  -Tool zmap             -Target <cidr>          [-Ports <ports>]
  
  # Web Application Security
  -Tool nikto            -Target <url>
  -Tool gobuster         -Target <url>           [-CustomArgs "<args>"]
  -Tool ffuf             -Target <url>           [-CustomArgs "<args>"]
  -Tool whatweb          -Target <url>
  -Tool wafw00f          -Target <url>
  -Tool dirb             -Target <url>
  
  # Vulnerability Scanning
  -Tool nuclei           -Target <url>           [-CustomArgs "<args>"]
  -Tool sqlmap           -Target <url>
  -Tool wpscan           -Target <url>
  
  # SSL/TLS Security Testing
  -Tool sslscan          -Target <host:port>
  -Tool testssl          -Target <host:port>
  -Tool sslyze           -Target <host:port>
  
  # Service Enumeration
  -Tool enum4linux       -Target <ip>
  -Tool smbclient        -Target <ip>            [-CustomArgs "<args>"]
  -Tool ldapsearch       -Target <ip>            [-CustomArgs "<args>"]
  -Tool snmpwalk         -Target <ip>            [-CustomArgs "<args>"]
  
  # Exploitation & Research
  -Tool searchsploit     -Target <keyword>
  -Tool msfconsole       -CustomArgs "<commands>"
  
  # Wireless Security (requires appropriate hardware)
  -Tool aircrack         -Target <capture_file>  [-CustomArgs "<args>"]
  -Tool wifite           -Target <interface>     [-CustomArgs "<args>"]
  
  # Forensics & Analysis
  -Tool binwalk          -Target <file_path>     [-CustomArgs "<args>"]
  -Tool strings          -Target <file_path>     [-CustomArgs "<args>"]
  -Tool file-analysis    -Target <file_path>
  
  # Custom & Utilities
  -Tool custom-nmap      -CustomArgs "<nmap-args>"     [-Iface <iface>]
  -Tool show-versions

Examples:
  # Network Scanning
  .\vult.ps1 -Tool quick-discovery -Target 10.10.30.0/24 -Iface eth0
  .\vult.ps1 -Tool masscan -Target 10.10.30.0/24 -Ports 80,443,22
  .\vult.ps1 -Tool rustscan -Target 10.10.30.5
  .\vult.ps1 -Tool specific-ports -Target 10.10.30.5 -Ports 80,443 -Iface eth0
  
  # Web Application Testing
  .\vult.ps1 -Tool nikto -Target http://target/
  .\vult.ps1 -Tool gobuster -Target http://target/ -CustomArgs "dir -w /usr/share/wordlists/dirb/common.txt"
  .\vult.ps1 -Tool whatweb -Target https://example.com
  .\vult.ps1 -Tool nuclei -Target https://example.com -CustomArgs "-t cves/"
  
  # SSL/TLS Testing
  .\vult.ps1 -Tool sslscan -Target example.com:443
  .\vult.ps1 -Tool testssl -Target https://example.com
  
  # Service Enumeration
  .\vult.ps1 -Tool enum4linux -Target 10.10.30.5
  .\vult.ps1 -Tool snmpwalk -Target 10.10.30.5 -CustomArgs "-v2c -c public"
  
  # Custom Commands
  .\vult.ps1 -Tool custom-nmap -CustomArgs "-sS -A 10.10.30.5" -Iface eth0

  # SSH Connection Examples
  .\vult.ps1 -Tool quick-discovery -Target 10.10.30.0/24 -SshHost 192.168.1.100 -SshUser root -SshKey C:\Users\user\.ssh\id_rsa
  .\vult.ps1 -Tool nuclei -Target https://example.com -SshHost kali.local -SshUser kali
  .\vult.ps1 -Tool masscan -Target 10.10.30.0/24 -Ports 80,443 -SshHost pentest-box -SshUser admin -SshKey C:\path\to\key
"@
}

# ---- SSH Connection Validation ----
if ($DebugMode) {
    Write-Host "[DEBUG] SSH Connection Parameters:"
    Write-Host "[DEBUG]   Host: $REMOTE_HOST"
    Write-Host "[DEBUG]   User: $REMOTE_USER"
    Write-Host "[DEBUG]   Key:  $SSH_KEY"
}

# Validate SSH key exists
if (-not (Test-Path $SSH_KEY)) {
    Write-Host "[ERROR] SSH key not found: $SSH_KEY" -ForegroundColor Red
    Write-Host "[ERROR] Please specify a valid SSH key path with -SshKey" -ForegroundColor Red
    exit 1
}

# ---- Remote Execution Functions ----
function Invoke-Remote {
    param([string]$Command)
    
    # Use cmd.exe to call ssh to avoid PowerShell command parsing issues
    $sshCmd = "ssh -t -i `"$SSH_KEY`" `"${REMOTE_USER}@${REMOTE_HOST}`" `"$Command`""
    cmd.exe /c $sshCmd
}

# ---- Dependency Management Functions ----
function Test-AndInstallDependencies {
    param([string]$Tool)
    
    Write-Host "[INFO] Checking dependencies for tool: $Tool"
    
    # Define tool-to-package mappings
    $toolPackages = ""
    switch ($Tool) {
        { $_ -in @("quick-discovery", "full-tcp", "specific-ports", "udp-scan", "custom-nmap") } {
            $toolPackages = "nmap"
        }
        "masscan" { $toolPackages = "masscan" }
        "rustscan" { $toolPackages = "rustscan" }
        "zmap" { $toolPackages = "zmap" }
        "nikto" { $toolPackages = "nikto" }
        "gobuster" { $toolPackages = "gobuster" }
        "ffuf" { $toolPackages = "ffuf" }
        "whatweb" { $toolPackages = "whatweb" }
        "wafw00f" { $toolPackages = "wafw00f" }
        "dirb" { $toolPackages = "dirb" }
        "nuclei" { $toolPackages = "nuclei" }
        "sqlmap" { $toolPackages = "sqlmap" }
        "wpscan" { $toolPackages = "wpscan" }
        "sslscan" { $toolPackages = "sslscan" }
        "testssl" { $toolPackages = "testssl.sh" }
        "sslyze" { $toolPackages = "sslyze" }
        "enum4linux" { $toolPackages = "enum4linux" }
        "smbclient" { $toolPackages = "smbclient" }
        "ldapsearch" { $toolPackages = "ldap-utils" }
        "snmpwalk" { $toolPackages = "snmp" }
        "searchsploit" { $toolPackages = "exploitdb" }
        "msfconsole" { $toolPackages = "metasploit-framework" }
        "aircrack" { $toolPackages = "aircrack-ng" }
        "wifite" { $toolPackages = "wifite" }
        "binwalk" { $toolPackages = "binwalk" }
        "strings" { $toolPackages = "binutils" }
        "file-analysis" { $toolPackages = "file" }
        default {
            Write-Host "[INFO] No specific package requirements for tool: $Tool"
            return
        }
    }
    
    # Check and install missing packages
    if (-not [string]::IsNullOrEmpty($toolPackages)) {
        $installScript = Get-PackageInstallScript $toolPackages
        Invoke-Remote $installScript
    }
}

function Get-PackageInstallScript {
    param([string]$Packages)
    
    # Return the bash script for package installation
    return @"
install_missing_packages() {
    local packages="$Packages"
    local missing_packages=""
    
    echo "[INFO] Checking package availability for: \$packages"
    
    for pkg in \$packages; do
        # Check if command exists or package is installed
        local cmd_to_check="\$pkg"
        
        # Handle special cases where command name differs from package
        case "\$pkg" in
            ldap-utils) cmd_to_check="ldapsearch" ;;
            binutils) cmd_to_check="strings" ;;
            exploitdb) cmd_to_check="searchsploit" ;;
            metasploit-framework) cmd_to_check="msfconsole" ;;
            testssl.sh) cmd_to_check="testssl" ;;
            snmp) cmd_to_check="snmpwalk" ;;
        esac
        
        if ! command -v "\$cmd_to_check" >/dev/null 2>&1; then
            echo "[WARN] Command '\$cmd_to_check' not found, marking package '\$pkg' for installation"
            missing_packages="\$missing_packages \$pkg"
        else
            echo "[OK] Command '\$cmd_to_check' is available"
        fi
    done
    
    # Install missing packages if any
    if [[ -n "\$missing_packages" ]]; then
        echo "[INFO] Installing missing packages:\$missing_packages"
        
        # Detect package manager and install
        if command -v apt-get >/dev/null 2>&1; then
            echo "[INFO] Using apt package manager"
            sudo apt-get update -qq
            for pkg in \$missing_packages; do
                case "\$pkg" in
                    rustscan)
                        # Install rustscan from GitHub if not available in repos
                        echo "[INFO] Installing rustscan from GitHub..."
                        if ! sudo apt-get install -y rustscan 2>/dev/null; then
                            echo "[INFO] Installing rustscan from releases..."
                            wget -q https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb -O /tmp/rustscan.deb
                            sudo dpkg -i /tmp/rustscan.deb || sudo apt-get install -f -y
                            rm -f /tmp/rustscan.deb
                        fi
                        ;;
                    nuclei)
                        echo "[INFO] Installing nuclei from GitHub..."
                        if ! sudo apt-get install -y nuclei 2>/dev/null; then
                            go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest 2>/dev/null || {
                                echo "[INFO] Installing nuclei binary..."
                                wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_2.9.15_linux_amd64.zip -O /tmp/nuclei.zip
                                unzip -q /tmp/nuclei.zip -d /tmp/
                                sudo mv /tmp/nuclei /usr/local/bin/
                                sudo chmod +x /usr/local/bin/nuclei
                                rm -f /tmp/nuclei.zip
                            }
                        fi
                        ;;
                    ffuf)
                        echo "[INFO] Installing ffuf..."
                        if ! sudo apt-get install -y ffuf 2>/dev/null; then
                            go install github.com/ffuf/ffuf@latest 2>/dev/null || {
                                wget -q https://github.com/ffuf/ffuf/releases/latest/download/ffuf_1.5.0_linux_amd64.tar.gz -O /tmp/ffuf.tar.gz
                                tar -xzf /tmp/ffuf.tar.gz -C /tmp/
                                sudo mv /tmp/ffuf /usr/local/bin/
                                sudo chmod +x /usr/local/bin/ffuf
                                rm -f /tmp/ffuf.tar.gz
                            }
                        fi
                        ;;
                    gobuster)
                        echo "[INFO] Installing gobuster..."
                        if ! sudo apt-get install -y gobuster 2>/dev/null; then
                            go install github.com/OJ/gobuster/v3@latest 2>/dev/null || {
                                wget -q https://github.com/OJ/gobuster/releases/latest/download/gobuster-linux-amd64.tar.gz -O /tmp/gobuster.tar.gz
                                tar -xzf /tmp/gobuster.tar.gz -C /tmp/
                                sudo mv /tmp/gobuster-linux-amd64/gobuster /usr/local/bin/
                                sudo chmod +x /usr/local/bin/gobuster
                                rm -rf /tmp/gobuster.tar.gz /tmp/gobuster-linux-amd64
                            }
                        fi
                        ;;
                    testssl.sh)
                        echo "[INFO] Installing testssl.sh..."
                        if ! command -v testssl >/dev/null 2>&1 && ! command -v testssl.sh >/dev/null 2>&1; then
                            sudo apt-get install -y testssl.sh 2>/dev/null || {
                                git clone --depth 1 https://github.com/drwetter/testssl.sh.git /tmp/testssl
                                sudo mv /tmp/testssl/testssl.sh /usr/local/bin/testssl
                                sudo chmod +x /usr/local/bin/testssl
                                rm -rf /tmp/testssl
                            }
                        fi
                        ;;
                    *)
                        echo "[INFO] Installing \$pkg via apt..."
                        sudo apt-get install -y "\$pkg" || echo "[WARN] Failed to install \$pkg"
                        ;;
                esac
            done
        elif command -v yum >/dev/null 2>&1; then
            echo "[INFO] Using yum package manager"
            for pkg in \$missing_packages; do
                sudo yum install -y "\$pkg" || echo "[WARN] Failed to install \$pkg"
            done
        elif command -v pacman >/dev/null 2>&1; then
            echo "[INFO] Using pacman package manager"
            for pkg in \$missing_packages; do
                sudo pacman -S --noconfirm "\$pkg" || echo "[WARN] Failed to install \$pkg"
            done
        else
            echo "[WARN] No supported package manager found (apt, yum, pacman)"
            echo "[WARN] Please manually install:\$missing_packages"
            return 1
        fi
        
        echo "[INFO] Package installation completed"
    else
        echo "[INFO] All required packages are already installed"
    fi
}

install_missing_packages
"@
}

# ---- Interface Helper Function ----
function Get-InterfaceIP {
    param([string]$Interface)
    
    if (-not [string]::IsNullOrEmpty($Interface)) {
        # Get IP address of the specified interface
        $ipCommand = "ip addr show $Interface | grep 'inet ' | awk '{print `$2}' | cut -d'/' -f1 | head -1"
        $result = Invoke-Remote $ipCommand
        return $result.Trim()
    }
    return ""
}

# ---- Universal Interface Forcing Function ----
function Invoke-WithInterface {
    param(
        [string]$Interface,
        [string]$Command
    )
    
    if ([string]::IsNullOrEmpty($Interface)) {
        Write-Host "[WARN] No interface specified, running command normally"
        return $Command
    }
    
    # Check if interface has IP address
    $interfaceIP = Get-InterfaceIP $Interface
    if ([string]::IsNullOrEmpty($interfaceIP)) {
        Write-Host "[WARN] Interface $Interface not found or has no IP, running without interface binding"
        return $Command
    }
    
    Write-Host "[INFO] Using network namespace to force interface $Interface (IP: $interfaceIP)"
    return "exec_in_netns $Interface `"$Command`""
}

# ---- PowerShell Network Namespace Function ----
function Invoke-InNetworkNamespace {
    param(
        [string]$Interface,
        [string]$Command
    )
    
    # This function will be sent to the remote host along with the bash exec_in_netns function
    $bashFunctions = @"
# PowerShell-Generated Bash Functions for Network Namespace Isolation
exec_in_netns() {
  local iface="`$1"
  local cmd="`$2"
  
  # Generate unique namespace name
  local netns_name="pentest_`${iface}_`$`$"
  
  # Get complete interface configuration before moving it
  local source_ip=`$(ip addr show `$iface 2>/dev/null | grep 'inet ' | awk '{print `$2}' | head -1)
  local broadcast=`$(ip addr show `$iface 2>/dev/null | grep 'inet ' | grep 'brd ' | awk '{for(i=1;i<=NF;i++) if(`$i=="brd") print `$(i+1)}' | head -1)
  local scope=`$(ip addr show `$iface 2>/dev/null | grep 'inet ' | grep 'scope ' | awk '{for(i=1;i<=NF;i++) if(`$i=="scope") print `$(i+1)}' | head -1)
  local iface_state=`$(ip link show `$iface 2>/dev/null | grep -o 'state [A-Z]*' | awk '{print `$2}')
  
  # Get the complete inet line for accurate restoration
  local inet_line=`$(ip addr show `$iface 2>/dev/null | grep 'inet ' | head -1)
  
  if [[ -z "`$source_ip" ]]; then
    echo "[WARN] Interface `$iface not found or has no IP, running command normally"
    eval "`$cmd"
    return
  fi
  
  echo "[INFO] Executing in isolated namespace for interface `$iface (IP: `${source_ip%/*})"
  
  # Create temporary network namespace
  sudo ip netns add `$netns_name 2>/dev/null || true

  # Set up signal traps for cleanup
  trap cleanup_netns EXIT INT TERM QUIT

  # Cleanup function
  cleanup_netns() {
    echo "[INFO] Restoring interface '`$iface' to main namespace (netns: '`$netns_name')"
    
    if ! sudo ip netns list 2>/dev/null | grep -q "`$netns_name"; then
      echo "[INFO] Namespace `$netns_name already cleaned up"
      return 0
    fi
    
    # Move interface back to main namespace
    if sudo ip netns exec `$netns_name ip link set `$iface netns 1 2>/dev/null; then
      echo "[INFO] Successfully moved `$iface back to main namespace"
    fi
    
    # Restore IP configuration
    if [[ -n "`$source_ip" ]]; then
      echo "[INFO] Restoring EXACT IP configuration for `$iface"
      echo "[DEBUG] Original inet line: `$inet_line"
      
      local add_cmd="sudo ip addr add `$source_ip dev `$iface"
      
      if [[ -n "`$broadcast" ]]; then
        add_cmd="`$add_cmd broadcast `$broadcast"
        echo "[DEBUG] Adding broadcast: `$broadcast"
      fi
      
      if [[ -n "`$scope" ]]; then
        add_cmd="`$add_cmd scope `$scope"
        echo "[DEBUG] Adding scope: `$scope"
      fi
      
      echo "[DEBUG] Executing compatible restoration: `$add_cmd"
      eval "`$add_cmd" 2>/dev/null || true
    fi
    
    # Restore interface state
    if [[ "`$iface_state" == "UP" ]]; then
      echo "[INFO] Bringing `$iface UP"
      sudo ip link set `$iface up 2>/dev/null || true
    fi
    
    # Clean up namespace
    sudo ip netns del `$netns_name 2>/dev/null || true
    
    echo "[INFO] Interface `$iface restored successfully"
  }

  # Move interface to namespace
  if sudo ip link set `$iface netns `$netns_name 2>/dev/null; then
    echo "[INFO] Successfully moved interface `$iface to namespace"
    
    sudo ip netns exec `$netns_name ip link set lo up 2>/dev/null || true
    sudo ip netns exec `$netns_name ip link set `$iface up 2>/dev/null || true
    
    if [[ -n "`$source_ip" ]]; then
      local ns_add_cmd="sudo ip netns exec `$netns_name ip addr add `$source_ip dev `$iface"
      
      if [[ -n "`$broadcast" ]]; then
        ns_add_cmd="`$ns_add_cmd broadcast `$broadcast"
      fi
      
      if [[ -n "`$scope" ]]; then
        ns_add_cmd="`$ns_add_cmd scope `$scope"
      fi
      
      echo "[DEBUG] Namespace IP setup with compatible attributes: `$ns_add_cmd"
      eval "`$ns_add_cmd" 2>/dev/null || true
    fi
    
    # Execute command in namespace
    sudo ip netns exec `$netns_name bash -c "`$cmd"
  else
    echo "[ERROR] Failed to move interface `$iface to namespace"
    eval "`$cmd"
  fi
}

# Cleanup orphaned namespaces function
cleanup_orphaned_namespaces() {
  echo "[INFO] Checking for orphaned pentest namespaces..."
  local orphaned_namespaces=`$(sudo ip netns list 2>/dev/null | grep "pentest_" | awk '{print `$1}')
  
  if [[ -n "`$orphaned_namespaces" ]]; then
    echo "[WARN] Found orphaned namespaces, attempting cleanup:"
    while IFS= read -r ns; do
      if [[ -n "`$ns" ]]; then
        echo "[INFO] Cleaning up orphaned namespace: `$ns"
        local iface_name=`$(echo "`$ns" | sed 's/pentest_\([^_]*\)_.*/\1/')
        
        if sudo ip netns exec "`$ns" ip link show "`$iface_name" &>/dev/null; then
          echo "[INFO] Moving `$iface_name back from orphaned namespace `$ns"
          sudo ip netns exec "`$ns" ip link set "`$iface_name" netns 1 2>/dev/null || true
        fi
        
        sudo ip netns del "`$ns" 2>/dev/null || true
        echo "[INFO] Removed orphaned namespace: `$ns"
      fi
    done <<< "`$orphaned_namespaces"
  else
    echo "[INFO] No orphaned namespaces found"
  fi
}
"@

    return $bashFunctions + "`nexec_in_netns $Interface `"$Command`""
}

# ---- Cleanup Namespace Function ----
function Invoke-CleanupNamespaces {
    Write-Host "[INFO] Cleaning up orphaned namespaces..."
    $cleanupScript = "cleanup_orphaned_namespaces() { echo `"[INFO] Checking for orphaned pentest namespaces...`"; local orphaned_namespaces=`$(sudo ip netns list 2>/dev/null | grep `"pentest_`" | awk '{print `$1}'); if [[ -n `"`$orphaned_namespaces`" ]]; then echo `"[WARN] Found orphaned namespaces, attempting cleanup:`"; while IFS= read -r ns; do if [[ -n `"`$ns`" ]]; then echo `"[INFO] Cleaning up orphaned namespace: `$ns`"; local iface_name=`$(echo `"`$ns`" | sed 's/pentest_\([^_]*\)_.*/\1/'); if sudo ip netns exec `"`$ns`" ip link show `"`$iface_name`" &>/dev/null; then echo `"[INFO] Moving `$iface_name back from orphaned namespace `$ns`"; sudo ip netns exec `"`$ns`" ip link set `"`$iface_name`" netns 1 2>/dev/null || true; fi; sudo ip netns del `"`$ns`" 2>/dev/null || true; echo `"[INFO] Removed orphaned namespace: `$ns`"; fi; done <<< `"`$orphaned_namespaces`"; else echo `"[INFO] No orphaned namespaces found`"; fi; }; cleanup_orphaned_namespaces"
    
    Invoke-Remote $cleanupScript
}

# ---- Log Cleanup Function ----
function Invoke-LogCleanup {
    $logDir = "logs"
    $maxLogs = 50
    
    if (-not (Test-Path $logDir)) {
        return
    }
    
    # Get all scan log files sorted by creation time
    $logFiles = Get-ChildItem -Path $logDir -Name "scan_*.log" -File | 
                Sort-Object CreationTime
    
    $logCount = $logFiles.Count
    
    if ($logCount -gt $maxLogs) {
        Write-Host "[INFO] Found $logCount log files, keeping only the latest $maxLogs"
        
        # Calculate how many files to delete
        $filesToDelete = $logCount - $maxLogs
        
        # Delete the oldest files
        $logFiles | Select-Object -First $filesToDelete | ForEach-Object {
            Remove-Item -Path (Join-Path $logDir $_) -Force
        }
        
        $remaining = (Get-ChildItem -Path $logDir -Name "scan_*.log" -File).Count
        Write-Host "[INFO] Cleaned up old logs, $remaining log files remaining"
    }
}

function Invoke-AndLog {
    param(
        [string]$Label,
        [string]$Command
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $logFile = "logs/scan_${timestamp}_${Label}.log"
    
    # Create logs directory if it doesn't exist
    if (-not (Test-Path "logs")) {
        New-Item -ItemType Directory -Path "logs" | Out-Null
    }
    
    # Clean up old logs before creating new one
    Invoke-LogCleanup
    
    # Check and install dependencies for the current tool
    Test-AndInstallDependencies $Label
    
    Write-Host "[INFO] Executing remotely: $Command"
    
    try {
        # Check if this is a namespace command
        if ($Command -match "^exec_in_netns") {
            # Extract interface and actual command
            if ($Command -match '^exec_in_netns (\S+) "(.+)"$') {
                $iface = $Matches[1]
                $actualCmd = $Matches[2]
                
                Write-Host "[INFO] Executing in network namespace for interface ${iface}: $actualCmd"
                
                # Get the bash functions and execute
                $namespaceFunctions = Invoke-InNetworkNamespace $iface $actualCmd
                $result = Invoke-Remote $namespaceFunctions
            } else {
                $result = Invoke-Remote $Command
            }
        } else {
            $result = Invoke-Remote $Command
        }
        
        $result | Tee-Object -FilePath $logFile
        Write-Host "[INFO] Saved output -> $logFile"
    }
    catch {
        Write-Host "[WARN] Command exited with non-zero status (logged)"
    }
}

# ---- Help Check ----
if ($Tool -eq "help" -or $Tool -eq "h") {
    Show-Usage
    exit 0
}

# ---- Cleanup Namespaces Check ----
if ($CleanupNamespaces) {
    Invoke-CleanupNamespaces
    exit 0
}

# ---- Tool Validation ----
if ([string]::IsNullOrEmpty($Tool)) {
    Write-Host "Error: -Tool is required."
    Show-Usage
    exit 1
}

# ---- Tool Execution ----
switch ($Tool) {
    "quick-discovery" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <cidr>"
            Show-Usage
            exit 1
        }
        $command = Invoke-WithInterface $Iface "nmap -sn $Target"
        Invoke-AndLog "discovery" $command
    }
    
    "full-tcp" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <targets>"
            Show-Usage
            exit 1
        }
        $command = Invoke-WithInterface $Iface "nmap -sC -sV -T4 $Target"
        Invoke-AndLog "fulltcp" $command
    }
    
    "specific-ports" {
        if ([string]::IsNullOrEmpty($Target) -or [string]::IsNullOrEmpty($Ports)) {
            Write-Host "Missing -Target <target> and/or -Ports <ports>"
            Show-Usage
            exit 1
        }
        $command = Invoke-WithInterface $Iface "nmap -sC -sV -p $Ports $Target"
        Invoke-AndLog "ports" $command
    }
    
    "udp-scan" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <target>"
            Show-Usage
            exit 1
        }
        $command = Invoke-WithInterface $Iface "nmap -sU --top-ports 100 $Target"
        Invoke-AndLog "udp" $command
    }
    
    "nikto" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <url>"
            Show-Usage
            exit 1
        }
        Invoke-AndLog "nikto" "nikto -host $Target"
    }
    
    "sqlmap" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <url>"
            Show-Usage
            exit 1
        }
        Invoke-AndLog "sqlmap" "sqlmap -u '$Target' --batch --random-agent --level=1 --risk=1"
    }
    
    "wpscan" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <url>"
            Show-Usage
            exit 1
        }
        Invoke-AndLog "wpscan" "wpscan --url $Target --enumerate p,t,u --plugins-detection mixed"
    }
    
    "dirb" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <url>"
            Show-Usage
            exit 1
        }
        Invoke-AndLog "dirb" "dirb $Target"
    }
    
    "searchsploit" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <keyword>"
            Show-Usage
            exit 1
        }
        Invoke-AndLog "searchsploit" "searchsploit $Target"
    }
    
    "custom-nmap" {
        if ([string]::IsNullOrEmpty($CustomArgs)) {
            Write-Host "Missing -CustomArgs `"<nmap-args>`""
            Show-Usage
            exit 1
        }
        $command = Invoke-WithInterface $Iface "nmap $CustomArgs"
        Invoke-AndLog "custom" $command
    }
    
    # ---- Additional Network Scanning Tools ----
    "masscan" {
        if ([string]::IsNullOrEmpty($Target) -or [string]::IsNullOrEmpty($Ports)) {
            Write-Host "Missing -Target <target> and/or -Ports <ports>"
            Show-Usage
            exit 1
        }
        $customArg = if ($CustomArgs) { $CustomArgs } else { "" }
        $command = Invoke-WithInterface $Iface "masscan -p$Ports $Target --rate=1000 $customArg"
        Invoke-AndLog "masscan" $command
    }
    
    "rustscan" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <target>"
            Show-Usage
            exit 1
        }
        $portsArg = if ($Ports) { "-p $Ports" } else { "" }
        $command = Invoke-WithInterface $Iface "rustscan -a $Target $portsArg --ulimit 5000"
        Invoke-AndLog "rustscan" $command
    }
    
    "zmap" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <cidr>"
            Show-Usage
            exit 1
        }
        $portsArg = if ($Ports) { "-p $Ports" } else { "-p 80" }
        $command = Invoke-WithInterface $Iface "zmap $portsArg $Target"
        Invoke-AndLog "zmap" $command
    }
    
    # ---- Web Application Security Tools ----
    "gobuster" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <url>"
            Show-Usage
            exit 1
        }
        $customArg = if ($CustomArgs) { $CustomArgs } else { "dir -w /usr/share/wordlists/dirb/common.txt" }
        Invoke-AndLog "gobuster" "gobuster $customArg -u $Target"
    }
    
    "ffuf" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <url>"
            Show-Usage
            exit 1
        }
        $customArg = if ($CustomArgs) { $CustomArgs } else { "-w /usr/share/wordlists/dirb/common.txt:FUZZ" }
        Invoke-AndLog "ffuf" "ffuf $customArg -u $Target/FUZZ"
    }
    
    "whatweb" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <url>"
            Show-Usage
            exit 1
        }
        $command = Invoke-WithInterface $Iface "whatweb $Target"
        Invoke-AndLog "whatweb" $command
    }
    
    "wafw00f" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <url>"
            Show-Usage
            exit 1
        }
        Invoke-AndLog "wafw00f" "wafw00f $Target"
    }
    
    # ---- Vulnerability Scanning Tools ----
    "nuclei" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <url>"
            Show-Usage
            exit 1
        }
        $customArg = if ($CustomArgs) { $CustomArgs } else { "-t cves/ -t vulnerabilities/" }
        Invoke-AndLog "nuclei" "nuclei -u $Target $customArg"
    }
    
    # ---- SSL/TLS Security Testing Tools ----
    "sslscan" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <host:port>"
            Show-Usage
            exit 1
        }
        Invoke-AndLog "sslscan" "sslscan $Target"
    }
    
    "testssl" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <host:port>"
            Show-Usage
            exit 1
        }
        Invoke-AndLog "testssl" "testssl $Target"
    }
    
    "sslyze" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <host:port>"
            Show-Usage
            exit 1
        }
        Invoke-AndLog "sslyze" "sslyze $Target"
    }
    
    # ---- Service Enumeration Tools ----
    "enum4linux" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <ip>"
            Show-Usage
            exit 1
        }
        Invoke-AndLog "enum4linux" "enum4linux $Target"
    }
    
    "smbclient" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <ip>"
            Show-Usage
            exit 1
        }
        $customArg = if ($CustomArgs) { $CustomArgs } else { "-L $Target -N" }
        Invoke-AndLog "smbclient" "smbclient $customArg"
    }
    
    "ldapsearch" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <ip>"
            Show-Usage
            exit 1
        }
        $customArg = if ($CustomArgs) { $CustomArgs } else { "-x -H ldap://$Target -s base namingcontexts" }
        Invoke-AndLog "ldapsearch" "ldapsearch $customArg"
    }
    
    "snmpwalk" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <ip>"
            Show-Usage
            exit 1
        }
        $customArg = if ($CustomArgs) { $CustomArgs } else { "-v2c -c public $Target" }
        Invoke-AndLog "snmpwalk" "snmpwalk $customArg"
    }
    
    # ---- Exploitation & Research Tools ----
    "msfconsole" {
        if ([string]::IsNullOrEmpty($CustomArgs)) {
            Write-Host "Missing -CustomArgs `"<commands>`""
            Write-Host "Example: -CustomArgs `"use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.10.30.5; check`""
            Show-Usage
            exit 1
        }
        Invoke-AndLog "msfconsole" "msfconsole -q -x '$CustomArgs; exit'"
    }
    
    # ---- Wireless Security Tools ----
    "aircrack" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <capture_file>"
            Show-Usage
            exit 1
        }
        $customArg = if ($CustomArgs) { $CustomArgs } else { "" }
        Invoke-AndLog "aircrack" "aircrack-ng $customArg $Target"
    }
    
    "wifite" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <interface>"
            Show-Usage
            exit 1
        }
        $customArg = if ($CustomArgs) { $CustomArgs } else { "" }
        Invoke-AndLog "wifite" "/usr/sbin/wifite -i $Target $customArg"
    }
    
    # ---- Forensics & Analysis Tools ----
    "binwalk" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <file_path>"
            Show-Usage
            exit 1
        }
        $customArg = if ($CustomArgs) { $CustomArgs } else { "-e" }
        Invoke-AndLog "binwalk" "binwalk $customArg $Target"
    }
    
    "strings" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <file_path>"
            Show-Usage
            exit 1
        }
        $customArg = if ($CustomArgs) { $CustomArgs } else { "" }
        Invoke-AndLog "strings" "strings $customArg $Target"
    }
    
    "file-analysis" {
        if ([string]::IsNullOrEmpty($Target)) {
            Write-Host "Missing -Target <file_path>"
            Show-Usage
            exit 1
        }
        Invoke-AndLog "file-analysis" "file $Target && hexdump -C $Target | head -20 && strings $Target | head -50"
    }
    
    "show-versions" {
        Invoke-AndLog "versions" "(echo '=== Network Tools ==='; nmap --version; masscan --version; rustscan --version; echo ''; echo '=== Web Tools ==='; nikto -Version 2>&1 | head -n1; gobuster version; ffuf -V; whatweb --version; wafw00f --version; echo ''; echo '=== Vulnerability Scanners ==='; nuclei -version; sqlmap --version 2>&1 | head -n1; wpscan --version 2>&1 | head -n1; echo ''; echo '=== SSL/TLS Tools ==='; sslscan --version; testssl.sh --version; sslyze --version; echo ''; echo '=== Enumeration Tools ==='; enum4linux -h | head -n1; smbclient --version; ldapsearch -VV 2>&1 | head -n1; snmpwalk -V 2>&1 | head -n1; echo ''; echo '=== Exploitation Tools ==='; searchsploit -v; msfconsole --version; echo ''; echo '=== Wireless Tools ==='; aircrack-ng --help | head -n1; /usr/sbin/wifite --help | head -n1; echo ''; echo '=== Forensics Tools ==='; binwalk --help | head -n1; strings --version; file --version)"
    }
    
    default {
        Write-Host "Unknown tool: $Tool"
        Show-Usage
        exit 1
    }
}