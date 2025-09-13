#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ---- Configuration ----
REMOTE_HOST=${REMOTE_HOST:-12.34.56.78}
REMOTE_USER=${REMOTE_USER:-kali}
SSH_KEY=${SSH_KEY:-/c/Users/user.name/.ssh/kali}

# ---- Usage ----
usage() {
  cat <<'USAGE'
Vult (Bash) - All-in-One Vulnerability Scanner
Usage:
  bash vult.sh --tool <tool> [--target <target>] [--iface <iface>] [--ports <ports>] [--args "<custom_args>"] [--ssh-host <host>] [--ssh-user <user>] [--ssh-key <path>] [--local]

Execution Mode:
  --local                 Run directly on local system (skip SSH remote execution)
  
SSH Connection Options (ignored if --local is used):
  --ssh-host <host>       SSH host/IP address (default: $REMOTE_HOST)
  --ssh-user <user>       SSH username (default: $REMOTE_USER)
  --ssh-key <path>        SSH private key path (default: $SSH_KEY)

Other Options:
  --debug                 Enable debug output showing execution details
  --cleanup-namespaces    Clean up orphaned network namespaces

Note: Log files are automatically cleaned up to keep only the latest 50 scan logs.

Available Tools:
  # Network Discovery & Port Scanning
  --tool quick-discovery   --target <cidr>         [--iface <iface>]
  --tool full-tcp         --target <targets>       [--iface <iface>]
  --tool specific-ports   --target <target> --ports <ports> [--iface <iface>]
  --tool udp-scan         --target <target>        [--iface <iface>]
  --tool masscan          --target <target> --ports <ports> [--iface <iface>] [--args "<args>"]
  --tool rustscan         --target <target>        [--iface <iface>] [--ports <ports>]
  --tool zmap             --target <cidr>          [--iface <iface>] [--ports <ports>]
  
  # Web Application Security
  --tool nikto            --target <url>           [--iface <iface>]
  --tool gobuster         --target <url>           [--iface <iface>] [--args "<args>"]
  --tool ffuf             --target <url>           [--iface <iface>] [--args "<args>"]
  --tool whatweb          --target <url>           [--iface <iface>]
  --tool wafw00f          --target <url>           [--iface <iface>]
  --tool dirb             --target <url>           [--iface <iface>]
  
  # Vulnerability Scanning
  --tool nuclei           --target <url>           [--iface <iface>] [--args "<args>"]
  --tool sqlmap           --target <url>           [--iface <iface>]
  --tool wpscan           --target <url>           [--iface <iface>]
  
  # SSL/TLS Security Testing
  --tool sslscan          --target <host:port>     [--iface <iface>]
  --tool testssl          --target <host:port>     [--iface <iface>]
  --tool sslyze           --target <host:port>     [--iface <iface>]
  
  # Service Enumeration
  --tool enum4linux       --target <ip>
  --tool smbclient        --target <ip>            [--args "<args>"]
  --tool ldapsearch       --target <ip>            [--args "<args>"]
  --tool snmpwalk         --target <ip>            [--args "<args>"]
  
  # Exploitation & Research
  --tool searchsploit     --target <keyword>
  --tool msfconsole       --args "<commands>"
  
  # Wireless Security (requires appropriate hardware)
  --tool aircrack         --target <capture_file>  [--args "<args>"]
  --tool wifite           --target <interface>     [--args "<args>"]
  
  # Forensics & Analysis
  --tool binwalk          --target <file_path>     [--args "<args>"]
  --tool strings          --target <file_path>     [--args "<args>"]
  --tool file-analysis    --target <file_path>
  
  # Custom & Utilities
  --tool custom-nmap      --args "<nmap-args>"     [--iface <iface>]
  --tool show-versions
  --cleanup-namespaces                              # Clean up orphaned namespaces

Examples:
  # Local Execution (when running on Kali/pentest box)
  bash vult.sh --local --tool quick-discovery --target 10.10.30.0/24 --iface eth0
  bash vult.sh --local --tool nikto --target http://target/
  bash vult.sh --local --tool nuclei --target https://example.com --args "-t cves/"

  # Remote Execution (from Windows/other systems via SSH)
  bash vult.sh --tool quick-discovery --target 10.10.30.0/24 --iface eth0
  bash vult.sh --tool masscan --target 10.10.30.0/24 --ports 80,443,22
  bash vult.sh --tool rustscan --target 10.10.30.5
  bash vult.sh --tool specific-ports --target 10.10.30.5 --ports 80,443 --iface eth0

  # Web Application Testing
  bash vult.sh --tool nikto --target http://target/
  bash vult.sh --tool gobuster --target http://target/ --args "dir -w /usr/share/wordlists/dirb/common.txt"
  bash vult.sh --tool whatweb --target https://example.com
  bash vult.sh --tool nuclei --target https://example.com --args "-t cves/"

  # SSL/TLS Testing
  bash vult.sh --tool sslscan --target example.com:443
  bash vult.sh --tool testssl --target https://example.com

  # Service Enumeration
  bash vult.sh --tool enum4linux --target 10.10.30.5
  bash vult.sh --tool snmpwalk --target 10.10.30.5 --args "-v2c -c public"

  # Custom Commands
  bash vult.sh --tool custom-nmap --args "-sS -A 10.10.30.5" --iface eth0

  # SSH Connection Examples (remote execution)
  bash vult.sh --tool quick-discovery --target 10.10.30.0/24 --ssh-host 192.168.1.100 --ssh-user root --ssh-key ~/.ssh/id_rsa
  bash vult.sh --tool nuclei --target https://example.com --ssh-host kali.local --ssh-user kali
  bash vult.sh --tool masscan --target 10.10.30.0/24 --ports 80,443 --ssh-host pentest-box --ssh-user admin --ssh-key /path/to/key
USAGE
}

# ---- Argument Parsing ----
TOOL=""
TARGET=""
IFACE=""
PORTS=""
ARGS=""
FORCE_INTERFACE="false"
CLEANUP_MODE="false"
LOCAL_MODE="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tool) TOOL="$2"; shift 2;;
    --target) TARGET="$2"; shift 2;;
    --iface) IFACE="$2"; shift 2;;
    --ports) PORTS="$2"; shift 2;;
    --args) ARGS="$2"; shift 2;;
    --ssh-host) REMOTE_HOST="$2"; shift 2;;
    --ssh-user) REMOTE_USER="$2"; shift 2;;
    --ssh-key) SSH_KEY="$2"; shift 2;;
    --debug) DEBUG="true"; shift 1;;
    --local) LOCAL_MODE="true"; shift 1;;
    --force-interface) FORCE_INTERFACE="true"; shift 1;;
    --cleanup-namespaces) CLEANUP_MODE="true"; shift 1;;
    --help|-h) usage; exit 0;;
    *) echo "Unknown argument: $1"; usage; exit 1;;
  esac
done

if [[ -z "$TOOL" && "$CLEANUP_MODE" != "true" ]]; then
  echo "Error: --tool is required."; usage; exit 1
fi

# ---- Debug Output ----
if [[ "${DEBUG:-}" == "true" ]]; then
  echo "[DEBUG] Execution Mode: $([ "$LOCAL_MODE" == "true" ] && echo "LOCAL" || echo "REMOTE via SSH")"
  if [[ "$LOCAL_MODE" != "true" ]]; then
    echo "[DEBUG] SSH Connection Parameters:"
    echo "[DEBUG]   Host: ${REMOTE_HOST}"
    echo "[DEBUG]   User: ${REMOTE_USER}"
    echo "[DEBUG]   Key:  ${SSH_KEY}"
  fi
fi

# ---- SSH Connection Validation (only for remote mode) ----
if [[ "$LOCAL_MODE" != "true" ]]; then
  # Validate SSH key exists
  if [[ ! -f "$SSH_KEY" ]]; then
    echo "[ERROR] SSH key not found: $SSH_KEY"
    echo "[ERROR] Please specify a valid SSH key path with --ssh-key or use --local for local execution"
    exit 1
  fi
fi

# ---- Execution Functions ----
run_remote() {
  local cmd="$1"
  if [[ "$LOCAL_MODE" == "true" ]]; then
    # Execute locally
    eval "$cmd"
  else
    # Execute via SSH
    ssh -t -i "$SSH_KEY" "${REMOTE_USER}@${REMOTE_HOST}" "$cmd"
  fi
}

# ---- Dependency Management Functions ----
check_and_install_deps() {
  local tool="$1"
  echo "[INFO] Checking dependencies for tool: $tool"
  
  # Define tool-to-package mappings
  local tool_packages=""
  case "$tool" in
    quick-discovery|full-tcp|specific-ports|udp-scan|custom-nmap)
      tool_packages="nmap"
      ;;
    masscan)
      tool_packages="masscan"
      ;;
    rustscan)
      tool_packages="rustscan"
      ;;
    zmap)
      tool_packages="zmap"
      ;;
    nikto)
      tool_packages="nikto"
      ;;
    gobuster)
      tool_packages="gobuster"
      ;;
    ffuf)
      tool_packages="ffuf"
      ;;
    whatweb)
      tool_packages="whatweb"
      ;;
    wafw00f)
      tool_packages="wafw00f"
      ;;
    dirb)
      tool_packages="dirb"
      ;;
    nuclei)
      tool_packages="nuclei"
      ;;
    sqlmap)
      tool_packages="sqlmap"
      ;;
    wpscan)
      tool_packages="wpscan"
      ;;
    sslscan)
      tool_packages="sslscan"
      ;;
    testssl)
      tool_packages="testssl.sh"
      ;;
    sslyze)
      tool_packages="sslyze"
      ;;
    enum4linux)
      tool_packages="enum4linux"
      ;;
    smbclient)
      tool_packages="smbclient"
      ;;
    ldapsearch)
      tool_packages="ldap-utils"
      ;;
    snmpwalk)
      tool_packages="snmp"
      ;;
    searchsploit)
      tool_packages="exploitdb"
      ;;
    msfconsole)
      tool_packages="metasploit-framework"
      ;;
    aircrack)
      tool_packages="aircrack-ng"
      ;;
    wifite)
      tool_packages="wifite"
      ;;
    binwalk)
      tool_packages="binwalk"
      ;;
    strings)
      tool_packages="binutils"
      ;;
    file-analysis)
      tool_packages="file"
      ;;
    *)
      echo "[INFO] No specific package requirements for tool: $tool"
      return 0
      ;;
  esac
  
  # Check and install missing packages
  if [[ -n "$tool_packages" ]]; then
    if [[ "$LOCAL_MODE" == "true" ]]; then
      # Install locally
      install_missing_packages "$tool_packages"
    else
      # Install remotely
      run_remote "$(declare -f install_missing_packages); install_missing_packages '$tool_packages'"
    fi
  fi
}

# Function to be executed remotely for package installation
install_missing_packages() {
  local packages="$1"
  local missing_packages=""
  local install_commands=""
  
  echo "[INFO] Checking package availability for: $packages"
  
  for pkg in $packages; do
    # Check if command exists or package is installed
    local cmd_to_check="$pkg"
    
    # Handle special cases where command name differs from package
    case "$pkg" in
      ldap-utils) cmd_to_check="ldapsearch" ;;
      binutils) cmd_to_check="strings" ;;
      exploitdb) cmd_to_check="searchsploit" ;;
      metasploit-framework) cmd_to_check="msfconsole" ;;
      testssl.sh) cmd_to_check="testssl" ;;
      snmp) cmd_to_check="snmpwalk" ;;
    esac
    
    if ! command -v "$cmd_to_check" >/dev/null 2>&1; then
      echo "[WARN] Command '$cmd_to_check' not found, marking package '$pkg' for installation"
      missing_packages="$missing_packages $pkg"
    else
      echo "[OK] Command '$cmd_to_check' is available"
    fi
  done
  
  # Install missing packages if any
  if [[ -n "$missing_packages" ]]; then
    echo "[INFO] Installing missing packages:$missing_packages"
    
    # Detect package manager and install
    if command -v apt-get >/dev/null 2>&1; then
      echo "[INFO] Using apt package manager"
      sudo apt-get update -qq
      for pkg in $missing_packages; do
        case "$pkg" in
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
            echo "[INFO] Installing $pkg via apt..."
            sudo apt-get install -y "$pkg" || echo "[WARN] Failed to install $pkg"
            ;;
        esac
      done
    elif command -v yum >/dev/null 2>&1; then
      echo "[INFO] Using yum package manager"
      for pkg in $missing_packages; do
        sudo yum install -y "$pkg" || echo "[WARN] Failed to install $pkg"
      done
    elif command -v pacman >/dev/null 2>&1; then
      echo "[INFO] Using pacman package manager"
      for pkg in $missing_packages; do
        sudo pacman -S --noconfirm "$pkg" || echo "[WARN] Failed to install $pkg"
      done
    else
      echo "[WARN] No supported package manager found (apt, yum, pacman)"
      echo "[WARN] Please manually install:$missing_packages"
      return 1
    fi
    
    echo "[INFO] Package installation completed"
  else
    echo "[INFO] All required packages are already installed"
  fi
}

# ---- Interface Helper Function ----
get_interface_ip() {
  local iface="$1"
  if [[ -n "$iface" ]]; then
    # Get IP address of the specified interface
    run_remote "ip addr show $iface | grep 'inet ' | awk '{print \$2}' | cut -d'/' -f1 | head -1"
  fi
}

# ---- Universal Interface Forcing Function ----
force_interface_wrapper() {
  local iface="$1"
  local cmd="$2"
  
  if [[ -z "$iface" ]]; then
    # No interface specified, run command normally
    echo "$cmd"
    return
  fi
  
  # Get interface details
  local source_ip=$(get_interface_ip "$iface")
  if [[ -z "$source_ip" ]]; then
    echo "[WARN] Interface $iface not found or has no IP, running without interface binding" >&2
    echo "$cmd"
    return
  fi
  
  echo "[INFO] Using network namespace to force interface $iface (IP: $source_ip)" >&2
  
  # Return the command wrapped in namespace execution (simplified)
  echo "exec_in_netns $iface \"$cmd\""
}

# ---- Emergency Cleanup Function ----
cleanup_orphaned_namespaces() {
  echo "[INFO] Checking for orphaned pentest namespaces..."
  local orphaned_namespaces=$(sudo ip netns list 2>/dev/null | grep "pentest_" | awk '{print $1}')
  
  if [[ -n "$orphaned_namespaces" ]]; then
    echo "[WARN] Found orphaned namespaces, attempting cleanup:"
    while IFS= read -r ns; do
      if [[ -n "$ns" ]]; then
        echo "[INFO] Cleaning up orphaned namespace: $ns"
        
        # Extract interface name from namespace name (pentest_ethX_PID format)
        local iface_name=$(echo "$ns" | sed 's/pentest_\([^_]*\)_.*/\1/')
        
        # Try to move interface back to main namespace
        if sudo ip netns exec "$ns" ip link show "$iface_name" &>/dev/null; then
          echo "[INFO] Moving $iface_name back from orphaned namespace $ns"
          sudo ip netns exec "$ns" ip link set "$iface_name" netns 1 2>/dev/null || true
        fi
        
        # Remove the orphaned namespace
        sudo ip netns del "$ns" 2>/dev/null || true
      fi
    done <<< "$orphaned_namespaces"
    echo "[INFO] Orphaned namespace cleanup completed"
  else
    echo "[INFO] No orphaned namespaces found"
  fi
}

# ---- Network Namespace Execution Function ----
exec_in_netns() {
  local iface="$1"
  local cmd="$2"
  
  # Check for and cleanup any orphaned namespaces from previous interrupted executions
  cleanup_orphaned_namespaces
  
  # Generate unique namespace name
  local netns_name="pentest_${iface}_$$"
  
  # Get complete interface configuration before moving it
  local source_ip=$(ip addr show $iface 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)
  local broadcast=$(ip addr show $iface 2>/dev/null | grep 'inet ' | grep 'brd ' | awk '{for(i=1;i<=NF;i++) if($i=="brd") print $(i+1)}' | head -1)
  local scope=$(ip addr show $iface 2>/dev/null | grep 'inet ' | grep 'scope ' | awk '{for(i=1;i<=NF;i++) if($i=="scope") print $(i+1)}' | head -1)
  local gateway=$(ip route show dev $iface 2>/dev/null | grep -oP 'via \K[^\s]+' | head -1)
  local iface_state=$(ip link show $iface 2>/dev/null | grep -o 'state [A-Z]*' | awk '{print $2}')
  local mac_addr=$(ip link show $iface 2>/dev/null | grep -oP 'link/ether \K[^\s]+')
  
  # Get the complete inet line for accurate restoration and extract ALL attributes
  local inet_line=$(ip addr show $iface 2>/dev/null | grep 'inet ' | head -1)
  
  # Extract ALL attributes after the scope (dynamic, permanent, secondary, etc.)
  local additional_attrs=""
  local is_dynamic=false
  if [[ "$inet_line" =~ scope\ [^\ ]+\ (.+)$ ]]; then
    # Get everything after "scope <scope_value> "
    local raw_attrs=$(echo "$inet_line" | sed -n 's/.*scope [^ ]* \(.*\)/\1/p')
    
    # Check for dynamic attribute (which cannot be manually restored)
    if [[ "$raw_attrs" =~ dynamic ]]; then
      is_dynamic=true
      echo "[DEBUG] Interface has DHCP dynamic address - will restore without 'dynamic' flag"
      # Remove 'dynamic' from attributes since it cannot be manually set
      additional_attrs=$(echo "$raw_attrs" | sed 's/dynamic//' | sed 's/  */ /g' | xargs)
    else
      additional_attrs="$raw_attrs"
    fi
  elif [[ "$inet_line" =~ scope\ [^\ ]+$ ]]; then
    # No additional attributes after scope
    additional_attrs=""
  else
    # Check if there are attributes without explicit scope
    local raw_attrs=$(echo "$inet_line" | sed -n 's/.*inet [^ ]* \(.*\)/\1/p' | sed 's/brd [^ ]* //' | sed 's/scope [^ ]* //')
    if [[ "$raw_attrs" =~ dynamic ]]; then
      is_dynamic=true
      additional_attrs=$(echo "$raw_attrs" | sed 's/dynamic//' | sed 's/  */ /g' | xargs)
    else
      additional_attrs="$raw_attrs"
    fi
  fi
  
  if [[ -z "$source_ip" ]]; then
    echo "[WARN] Interface $iface not found or has no IP, running command normally"
    eval "$cmd"
    return
  fi
  
  echo "[INFO] Executing in isolated namespace for interface $iface (IP: ${source_ip%/*})"
  
  # Create temporary network namespace for interface isolation
  sudo ip netns add $netns_name 2>/dev/null || true

  # Set up signal traps to ensure cleanup happens even if command is interrupted
  trap cleanup_netns EXIT INT TERM QUIT

  # Enhanced cleanup function that saves/restores interface state
  local cleanup_success=0
  cleanup_netns() {
    if [[ $cleanup_success -eq 1 ]]; then
      echo "[INFO] Cleanup already performed for $iface"
      return  # Avoid duplicate cleanup
    fi
    cleanup_success=1
    
    echo "[INFO] Restoring interface '$iface' to main namespace (netns: '$netns_name')"
    
    # Debug: Check if variables are available
    if [[ -z "$iface" || -z "$netns_name" ]]; then
      echo "[WARN] Missing variables in cleanup - iface: '$iface', netns: '$netns_name'"
      return 1
    fi
    
    # Emergency cleanup: Check if namespace exists first
    if ! sudo ip netns list 2>/dev/null | grep -q "$netns_name"; then
      echo "[INFO] Namespace $netns_name already cleaned up"
      return 0
    fi
    
    # Move interface back to main namespace
    if sudo ip netns exec $netns_name ip link set $iface netns 1 2>/dev/null; then
      echo "[INFO] Successfully moved $iface back to main namespace"
    else
      echo "[WARN] Failed to move $iface back to main namespace (may already be restored)"
    fi
    
    # Restore complete interface configuration with ALL original attributes
    if [[ -n "$source_ip" ]]; then
      echo "[INFO] Restoring EXACT IP configuration for $iface"
      echo "[DEBUG] Original inet line: $inet_line"
      if [[ "$is_dynamic" == "true" ]]; then
        echo "[DEBUG] Note: 'dynamic' attribute detected but cannot be manually restored (DHCP-assigned)"
      fi
      
      # Build the ip addr add command with ALL compatible original parameters
      local add_cmd="sudo ip addr add $source_ip dev $iface"
      
      # Add broadcast address if it exists in the original configuration
      if [[ -n "$broadcast" ]]; then
        add_cmd="$add_cmd broadcast $broadcast"
        echo "[DEBUG] Adding broadcast: $broadcast"
      fi
      
      # Add scope if it exists in the original configuration
      if [[ -n "$scope" ]]; then
        add_cmd="$add_cmd scope $scope"
        echo "[DEBUG] Adding scope: $scope"
      fi
      
      # Add compatible additional attributes (excluding unsupported ones like 'dynamic')
      if [[ -n "$additional_attrs" && "$additional_attrs" != "$iface" ]]; then
        # Clean up the additional attributes (remove interface name if present at end)
        local clean_attrs=$(echo "$additional_attrs" | sed "s/ $iface$//" | xargs)
        if [[ -n "$clean_attrs" ]]; then
          add_cmd="$add_cmd $clean_attrs"
          echo "[DEBUG] Adding compatible additional attributes: $clean_attrs"
        fi
      fi
      
      # Execute the complete restoration command with ALL compatible original attributes
      echo "[DEBUG] Executing compatible restoration: $add_cmd"
      eval "$add_cmd" 2>/dev/null || true
      
      if [[ "$is_dynamic" == "true" ]]; then
        echo "[INFO] Interface restored (Note: 'dynamic' flag indicates original DHCP assignment)"
      fi
    fi
    
    # Restore interface state (UP/DOWN)
    if [[ "$iface_state" == "UP" ]]; then
      echo "[INFO] Bringing $iface UP"
      sudo ip link set $iface up 2>/dev/null || true
    fi
    
    # Restore routes if gateway exists
    if [[ -n "$gateway" ]]; then
      # Only add route if it doesn't already exist
      ip route show | grep -q "dev $iface" || sudo ip route add default via $gateway dev $iface 2>/dev/null || true
    fi
    
    # Clean up namespace
    sudo ip netns del $netns_name 2>/dev/null || true
    
    # Clean up any veth pairs
    sudo iptables -t nat -D POSTROUTING -s 192.168.100.0/24 -o $iface -j MASQUERADE 2>/dev/null || true
    sudo ip link del veth0_$netns_name 2>/dev/null || true
    
    echo "[INFO] Interface $iface restored successfully"
  }

  # Try to move interface to namespace temporarily  
  if sudo ip link set $iface netns $netns_name 2>/dev/null; then
    echo "[INFO] Successfully moved interface $iface to namespace"
    
    # Setup interface in namespace with complete configuration including compatible attributes
    sudo ip netns exec $netns_name ip link set lo up 2>/dev/null || true
    sudo ip netns exec $netns_name ip link set $iface up 2>/dev/null || true
    
    # Restore complete IP configuration in namespace with ALL compatible original attributes
    if [[ -n "$source_ip" ]]; then
      local ns_add_cmd="sudo ip netns exec $netns_name ip addr add $source_ip dev $iface"
      
      # Add broadcast address if it exists
      if [[ -n "$broadcast" ]]; then
        ns_add_cmd="$ns_add_cmd broadcast $broadcast"
      fi
      
      # Add scope if it exists  
      if [[ -n "$scope" ]]; then
        ns_add_cmd="$ns_add_cmd scope $scope"
      fi
      
      # Add compatible additional attributes (excluding unsupported ones like 'dynamic')
      if [[ -n "$additional_attrs" && "$additional_attrs" != "$iface" ]]; then
        local clean_attrs=$(echo "$additional_attrs" | sed "s/ $iface$//" | xargs)
        if [[ -n "$clean_attrs" ]]; then
          ns_add_cmd="$ns_add_cmd $clean_attrs"
        fi
      fi
      
      echo "[DEBUG] Namespace IP setup with compatible attributes: $ns_add_cmd"
      eval "$ns_add_cmd" 2>/dev/null || true
    fi

    # Add default route through the interface's gateway if available
    if [[ -n "$gateway" ]]; then
      sudo ip netns exec $netns_name ip route add default via $gateway dev $iface 2>/dev/null || true
    fi

    # Execute command in isolated namespace with signal handling
    sudo ip netns exec $netns_name bash -c "$cmd"
    
    # Explicit cleanup call after successful command completion
    cleanup_netns
    
  else
    echo "[INFO] Cannot move interface, using veth pair method for isolation"
    
    # Alternative: Create veth pair and route through specific interface
    sudo ip link add veth0_$netns_name type veth peer name veth1_$netns_name 2>/dev/null || true
    sudo ip link set veth1_$netns_name netns $netns_name 2>/dev/null || true
    sudo ip netns exec $netns_name ip link set lo up 2>/dev/null || true
    sudo ip netns exec $netns_name ip link set veth1_$netns_name up 2>/dev/null || true
    sudo ip netns exec $netns_name ip addr add 192.168.100.2/24 dev veth1_$netns_name 2>/dev/null || true
    sudo ip link set veth0_$netns_name up 2>/dev/null || true
    sudo ip addr add 192.168.100.1/24 dev veth0_$netns_name 2>/dev/null || true
    
    # Route traffic through specified interface
    sudo ip netns exec $netns_name ip route add default via 192.168.100.1 dev veth1_$netns_name 2>/dev/null || true
    sudo iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -o $iface -j MASQUERADE 2>/dev/null || true
    
    # Execute command in namespace with signal handling
    sudo ip netns exec $netns_name bash -c "$cmd"
    
    # Explicit cleanup call after successful command completion
    cleanup_netns
  fi
}

# ---- Log Cleanup Function ----
cleanup_old_logs() {
  local log_dir="logs"
  local max_logs=50
  
  if [[ ! -d "$log_dir" ]]; then
    return 0
  fi
  
  # Count current log files
  local log_count=$(find "$log_dir" -name "scan_*.log" -type f | wc -l)
  
  if (( log_count > max_logs )); then
    echo "[INFO] Found $log_count log files, keeping only the latest $max_logs"
    
    # Delete oldest logs, keeping the newest 50
    find "$log_dir" -name "scan_*.log" -type f -printf '%T@ %p\n' | \
      sort -n | \
      head -n -${max_logs} | \
      cut -d' ' -f2- | \
      xargs -r rm -f
      
    local remaining=$(find "$log_dir" -name "scan_*.log" -type f | wc -l)
    echo "[INFO] Cleaned up old logs, $remaining log files remaining"
  fi
}

run_and_log() {
  local label="$1"; shift
  local cmd="$*"
  local lf="logs/scan_$(date +"%Y%m%d-%H%M%S")_${label}.log"
  mkdir -p logs
  
  # Clean up old logs before creating new one
  cleanup_old_logs
  
  # Check and install dependencies for the current tool
  check_and_install_deps "$label"
  
  local execution_mode=$([ "$LOCAL_MODE" == "true" ] && echo "locally" || echo "remotely")
  echo "[INFO] Executing $execution_mode: $cmd"
  
  # Check if this is a namespace execution command
  if [[ "$cmd" =~ ^exec_in_netns ]]; then
    # Extract namespace execution parameters
    local iface=$(echo "$cmd" | awk '{print $2}')
    local actual_cmd=$(echo "$cmd" | sed 's/^exec_in_netns [^ ]* "//' | sed 's/"$//')
    
    echo "[INFO] Executing in network namespace for interface $iface: $actual_cmd"
    
    if [[ "$LOCAL_MODE" == "true" ]]; then
      # Local execution - call function directly
      if exec_in_netns "$iface" "$actual_cmd" | tee "$lf"; then
        echo "[INFO] Saved output -> $lf"
      else
        echo "[WARN] Command exited with non-zero status (logged)"
      fi
    else
      # Remote execution - send function definition and execute
      if run_remote "$(declare -f exec_in_netns get_interface_ip); exec_in_netns $iface \"$actual_cmd\"" | tee "$lf"; then
        echo "[INFO] Saved output -> $lf"
      else
        echo "[WARN] Command exited with non-zero status (logged)"
      fi
    fi
  else
    # Normal execution
    if run_remote "$cmd" | tee "$lf"; then
      echo "[INFO] Saved output -> $lf"
    else
      echo "[WARN] Command exited with non-zero status (logged)"
    fi
  fi
}

# Handle cleanup mode
if [[ "$CLEANUP_MODE" == "true" ]]; then
  echo "[INFO] Cleaning up orphaned namespaces..."
  if [[ "$LOCAL_MODE" == "true" ]]; then
    cleanup_orphaned_namespaces
  else
    run_remote "$(declare -f cleanup_orphaned_namespaces); cleanup_orphaned_namespaces"
  fi
  exit 0
fi

case "$TOOL" in
  quick-discovery)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <cidr>"; usage; exit 1; fi
    cmd="nmap -sn $TARGET"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log discovery "$cmd"
    ;;
  full-tcp)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <targets>"; usage; exit 1; fi
    cmd="nmap -sC -sV -T4 $TARGET"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log fulltcp "$cmd"
    ;;
  specific-ports)
    if [[ -z "$TARGET" || -z "$PORTS" ]]; then echo "Missing --target <target> and/or --ports <ports>"; usage; exit 1; fi
    cmd="nmap -sC -sV -p $PORTS $TARGET"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log ports "$cmd"
    ;;
  udp-scan)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <target>"; usage; exit 1; fi
    cmd="nmap -sU --top-ports 100 $TARGET"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log udp "$cmd"
    ;;
  nikto)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <url>"; usage; exit 1; fi
    cmd="nikto -host $TARGET"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log nikto "$cmd"
    ;;
  sqlmap)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <url>"; usage; exit 1; fi
    cmd="sqlmap -u '$TARGET' --batch --random-agent --level=1 --risk=1"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log sqlmap "$cmd"
    ;;
  wpscan)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <url>"; usage; exit 1; fi
    cmd="wpscan --url $TARGET --enumerate p,t,u --plugins-detection mixed"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log wpscan "$cmd"
    ;;
  dirb)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <url>"; usage; exit 1; fi
    cmd="dirb $TARGET"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log dirb "$cmd"
    ;;
  searchsploit)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <keyword>"; usage; exit 1; fi
    run_and_log searchsploit "searchsploit $TARGET"
    ;;
  custom-nmap)
    if [[ -z "$ARGS" ]]; then echo "Missing --args \"<nmap-args>\""; usage; exit 1; fi
    cmd="nmap $ARGS"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log custom "$cmd"
    ;;
  
  # ---- Additional Network Scanning Tools ----
  masscan)
    if [[ -z "$TARGET" || -z "$PORTS" ]]; then echo "Missing --target <target> and/or --ports <ports>"; usage; exit 1; fi
    custom_args="${ARGS:-}"
    cmd="sudo masscan -p$PORTS $TARGET --rate=1000 $custom_args"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log masscan "$cmd"
    ;;
  rustscan)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <target>"; usage; exit 1; fi
    ports_arg="${PORTS:+-p $PORTS}"
    cmd="rustscan -a $TARGET $ports_arg --ulimit 5000"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log rustscan "$cmd"
    ;;
  zmap)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <cidr>"; usage; exit 1; fi
    ports_arg="${PORTS:-80}"
    cmd="zmap -p $ports_arg $TARGET"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log zmap "$cmd"
    ;;
  
  # ---- Web Application Security Tools ----
  gobuster)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <url>"; usage; exit 1; fi
    custom_args="${ARGS:-dir -w /usr/share/wordlists/dirb/common.txt}"
    cmd="gobuster $custom_args -u $TARGET"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log gobuster "$cmd"
    ;;
  ffuf)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <url>"; usage; exit 1; fi
    custom_args="${ARGS:--w /usr/share/wordlists/dirb/common.txt:FUZZ}"
    cmd="ffuf $custom_args -u $TARGET/FUZZ"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log ffuf "$cmd"
    ;;
  whatweb)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <url>"; usage; exit 1; fi
    cmd="whatweb $TARGET"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log whatweb "$cmd"
    ;;
  wafw00f)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <url>"; usage; exit 1; fi
    cmd="wafw00f $TARGET"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log wafw00f "$cmd"
    ;;
  
  # ---- Vulnerability Scanning Tools ----
  nuclei)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <url>"; usage; exit 1; fi
    custom_args="${ARGS:--t cves/ -t vulnerabilities/}"
    cmd="nuclei -u $TARGET $custom_args"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log nuclei "$cmd"
    ;;
  
  # ---- SSL/TLS Security Testing Tools ----
  sslscan)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <host:port>"; usage; exit 1; fi
    cmd="sslscan $TARGET"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log sslscan "$cmd"
    ;;
  testssl)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <host:port>"; usage; exit 1; fi
    cmd="testssl $TARGET"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log testssl "$cmd"
    ;;
  sslyze)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <host:port>"; usage; exit 1; fi
    cmd="sslyze $TARGET"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log sslyze "$cmd"
    ;;
  
  # ---- Service Enumeration Tools ----
  enum4linux)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <ip>"; usage; exit 1; fi
    cmd="enum4linux $TARGET"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log enum4linux "$cmd"
    ;;
  smbclient)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <ip>"; usage; exit 1; fi
    custom_args="${ARGS:--L $TARGET -N}"
    cmd="smbclient $custom_args"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log smbclient "$cmd"
    ;;
  ldapsearch)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <ip>"; usage; exit 1; fi
    custom_args="${ARGS:--x -H ldap://$TARGET -s base namingcontexts}"
    cmd="ldapsearch $custom_args"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log ldapsearch "$cmd"
    ;;
  snmpwalk)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <ip>"; usage; exit 1; fi
    custom_args="${ARGS:--v2c -c public $TARGET}"
    cmd="snmpwalk $custom_args"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log snmpwalk "$cmd"
    ;;
  
  # ---- Exploitation & Research Tools ----
  msfconsole)
    if [[ -z "$ARGS" ]]; then 
      echo "Missing --args \"<commands>\""
      echo "Example: --args \"use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.10.30.5; check\""
      usage; exit 1
    fi
    cmd="msfconsole -q -x '$ARGS; exit'"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log msfconsole "$cmd"
    ;;
  
  # ---- Wireless Security Tools ----
  aircrack)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <capture_file>"; usage; exit 1; fi
    custom_args="${ARGS:-}"
    cmd="aircrack-ng $custom_args $TARGET"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log aircrack "$cmd"
    ;;
  wifite)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <interface>"; usage; exit 1; fi
    custom_args="${ARGS:-}"
    cmd="/usr/sbin/wifite -i $TARGET $custom_args"
    if [[ -n "$IFACE" ]]; then
      cmd=$(force_interface_wrapper "$IFACE" "$cmd")
    fi
    run_and_log wifite "$cmd"
    ;;
  
  # ---- Forensics & Analysis Tools ----
  binwalk)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <file_path>"; usage; exit 1; fi
    custom_args="${ARGS:--e}"
    run_and_log binwalk "binwalk $custom_args $TARGET"
    ;;
  strings)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <file_path>"; usage; exit 1; fi
    custom_args="${ARGS:-}"
    run_and_log strings "strings $custom_args $TARGET"
    ;;
  file-analysis)
    if [[ -z "$TARGET" ]]; then echo "Missing --target <file_path>"; usage; exit 1; fi
    run_and_log file-analysis "file $TARGET && hexdump -C $TARGET | head -20 && strings $TARGET | head -50"
    ;;
  show-versions)
    run_and_log versions "(echo '=== Network Tools ==='; nmap --version; masscan --version; rustscan --version; echo ''; echo '=== Web Tools ==='; nikto -Version 2>&1 | head -n1; gobuster version; ffuf -V; whatweb --version; wafw00f --version; echo ''; echo '=== Vulnerability Scanners ==='; nuclei -version; sqlmap --version 2>&1 | head -n1; wpscan --version 2>&1 | head -n1; echo ''; echo '=== SSL/TLS Tools ==='; sslscan --version; testssl.sh --version; sslyze --version; echo ''; echo '=== Enumeration Tools ==='; enum4linux -h | head -n1; smbclient --version; ldapsearch -VV 2>&1 | head -n1; snmpwalk -V 2>&1 | head -n1; echo ''; echo '=== Exploitation Tools ==='; searchsploit -v; msfconsole --version; echo ''; echo '=== Wireless Tools ==='; aircrack-ng --help | head -n1; /usr/sbin/wifite --help | head -n1; echo ''; echo '=== Forensics Tools ==='; binwalk --help | head -n1; strings --version; file --version)"
    ;;
  *)
    echo "Unknown tool: $TOOL"; usage; exit 1
    ;;
esac