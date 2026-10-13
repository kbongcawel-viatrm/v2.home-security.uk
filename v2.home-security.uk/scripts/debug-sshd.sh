#!/usr/bin/env bash
# Debug SSH daemon (sshd) issues on Fedora/Secureblue
# Run this on the TARGET HOST (Secureblue), not in Toolbox
#
# Usage: sudo ./scripts/debug-sshd.sh
# Or: run0 ./scripts/debug-sshd.sh

set -uo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
section() { echo ""; echo "=== $1 ==="; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo or run0)"
    exit 1
fi

section "System Information"
echo "Hostname: $(hostname)"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo "Kernel: $(uname -r)"
echo "SELinux: $(getenforce 2>/dev/null || echo 'unknown')"

section "1. Check if OpenSSH Server is Installed"
if rpm -q openssh-server &>/dev/null; then
    info "openssh-server is installed: $(rpm -q openssh-server)"
else
    error "openssh-server is NOT installed"
    echo "Install with: dnf install openssh-server"
fi

section "2. Check sshd Service Status"
if systemctl is-active sshd &>/dev/null; then
    info "sshd.service is ACTIVE (running)"
else
    error "sshd.service is NOT active"
    echo "Status: $(systemctl is-active sshd)"
    echo ""
    echo "Recent logs:"
    journalctl -u sshd -n 20 --no-pager
fi

echo ""
if systemctl is-enabled sshd &>/dev/null; then
    info "sshd.service is ENABLED (starts on boot)"
else
    warn "sshd.service is NOT enabled (won't start on boot)"
    echo "Enable with: systemctl enable sshd"
fi

section "3. Check sshd is Listening on Port 22"
if ss -tlnp | grep -q ':22 '; then
    info "sshd is listening on port 22"
    ss -tlnp | grep ':22 '
else
    error "sshd is NOT listening on port 22"
    echo "All listening ports:"
    ss -tlnp
fi

section "4. Check sshd Configuration"
info "sshd config file: /etc/ssh/sshd_config"
echo ""
echo "Key settings:"
grep -E '^(Port|ListenAddress|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AuthorizedKeysFile|PermitEmptyPasswords|AllowUsers|DenyUsers|AllowGroups|DenyGroups)' /etc/ssh/sshd_config 2>/dev/null || echo "No explicit settings found (using defaults)"

echo ""
echo "Include directories:"
grep -E '^Include' /etc/ssh/sshd_config 2>/dev/null || echo "No Include directives"

section "5. Validate sshd Configuration"
if sshd -t 2>&1; then
    info "sshd configuration is VALID"
else
    error "sshd configuration has ERRORS (shown above)"
fi

section "6. Check Firewall (firewalld)"
if systemctl is-active firewalld &>/dev/null; then
    info "firewalld is active"
    echo ""
    echo "SSH service in firewalld:"
    firewall-cmd --query-service=ssh && info "SSH service is ALLOWED in firewalld" || warn "SSH service is NOT allowed in firewalld"
    echo ""
    echo "Active zones:"
    firewall-cmd --get-active-zones
    echo ""
    echo "Services in default zone:"
    firewall-cmd --list-services
    echo ""
    echo "All rules for port 22:"
    firewall-cmd --list-all | grep -E '22|ssh' || echo "No specific rules for port 22"
else
    warn "firewalld is NOT active"
fi

section "7. Check SELinux Status"
if command -v getenforce &>/dev/null; then
    SELINUX_STATUS=$(getenforce)
    info "SELinux status: $SELINUX_STATUS"
    
    if [[ "$SELINUX_STATUS" == "Enforcing" ]]; then
        echo ""
        echo "SELinux denials for sshd (last 10):"
        ausearch -m avc -ts recent 2>/dev/null | grep sshd | tail -10 || echo "No recent SELinux denials for sshd"
        
        echo ""
        echo "SELinux boolean for ssh:"
        getsebool -a 2>/dev/null | grep ssh || echo "No SSH-related booleans found"
    fi
else
    warn "SELinux tools not found (getenforce)"
fi

section "8. Check SSH Host Keys"
echo "Host key files in /etc/ssh/:"
ls -la /etc/ssh/ssh_host_* 2>/dev/null || error "No SSH host keys found!"

if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
    warn "Ed25519 host key not found - generating..."
    ssh-keygen -A
fi

section "9. Check User SSH Directory (for authorized_keys)"
# Check for common users
for user in kim root; do
    if id "$user" &>/dev/null; then
        USER_HOME=$(getent passwd "$user" | cut -d: -f6)
        SSH_DIR="$USER_HOME/.ssh"
        AUTH_KEYS="$SSH_DIR/authorized_keys"
        
        echo ""
        echo "User: $user (home: $USER_HOME)"
        
        if [[ -d "$SSH_DIR" ]]; then
            info "SSH directory exists: $SSH_DIR"
            ls -la "$SSH_DIR"
            
            if [[ -f "$AUTH_KEYS" ]]; then
                info "authorized_keys exists: $AUTH_KEYS"
                echo "Number of keys: $(wc -l < "$AUTH_KEYS")"
                echo "Key types:"
                awk '{print $1}' "$AUTH_KEYS" | sort | uniq -c
            else
                warn "authorized_keys NOT found at $AUTH_KEYS"
            fi
        else
            warn "SSH directory NOT found: $SSH_DIR"
            echo "Create with: mkdir -p $SSH_DIR && chmod 700 $SSH_DIR"
        fi
    fi
done

section "10. Check Recent SSH Logs"
echo "Last 20 sshd log entries:"
journalctl -u sshd -n 20 --no-pager 2>/dev/null || echo "No logs found"

echo ""
echo "Authentication failures (last hour):"
journalctl -u sshd --since "1 hour ago" | grep -iE 'fail|error|invalid|denied' | tail -10 || echo "No recent failures"

section "11. Test Local SSH Connection"
info "Testing local SSH connection to localhost..."
if ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no localhost "echo 'Local SSH works'" 2>&1; then
    info "Local SSH connection successful"
else
    warn "Local SSH connection failed (this is expected if PasswordAuthentication is disabled and no key is set up for localhost)"
fi

section "12. Network Connectivity Check"
echo "Checking network interfaces:"
ip -brief address

echo ""
echo "Checking if port 22 is reachable from localhost:"
if nc -zv localhost 22 2>&1; then
    info "Port 22 is reachable locally"
else
    error "Port 22 is NOT reachable locally"
fi

section "13. Check for IP Restrictions"
echo "Checking /etc/hosts.allow and /etc/hosts.deny:"
if [[ -f /etc/hosts.allow ]]; then
    echo "hosts.allow:"
    cat /etc/hosts.allow | grep -v '^#' | grep -v '^$'
else
    echo "hosts.allow: not found"
fi
echo ""
if [[ -f /etc/hosts.deny ]]; then
    echo "hosts.deny:"
    cat /etc/hosts.deny | grep -v '^#' | grep -v '^$'
else
    echo "hosts.deny: not found"
fi

section "Summary and Recommendations"
echo ""
SSHD_ACTIVE=$(systemctl is-active sshd 2>/dev/null)
SSHD_ENABLED=$(systemctl is-enabled sshd 2>/dev/null)
FIREWALL_OK=$(firewall-cmd --query-service=ssh 2>/dev/null && echo "yes" || echo "no")

echo "Status Summary:"
echo "  sshd active: $SSHD_ACTIVE"
echo "  sshd enabled: $SSHD_ENABLED"
echo "  firewall allows SSH: $FIREWALL_OK"
echo ""

if [[ "$SSHD_ACTIVE" == "active" && "$SSHD_ENABLED" == "enabled" && "$FIREWALL_OK" == "yes" ]]; then
    info "SSH appears to be properly configured!"
    echo ""
    echo "Next steps:"
    echo "  1. Verify your SSH key is in ~/.ssh/authorized_keys for user 'kim'"
    echo "  2. Test from GitHub-hosted runner or your local machine:"
    echo "     ssh -i ~/.ssh/github_actions kim@$(hostname -I | awk '{print $1}')"
else
    echo ""
    warn "Issues found! Recommended fixes:"
    [[ "$SSHD_ACTIVE" != "active" ]] && echo "  - Start sshd: systemctl start sshd"
    [[ "$SSHD_ENABLED" != "enabled" ]] && echo "  - Enable sshd: systemctl enable sshd"
    [[ "$FIREWALL_OK" != "yes" ]] && echo "  - Allow SSH in firewall: firewall-cmd --permanent --add-service=ssh && firewall-cmd --reload"
    echo "  - Check logs: journalctl -u sshd -f"
fi

section "Quick Fix Commands"
echo "If SSH is not working, try these commands:"
echo ""
echo "# Restart SSH service"
echo "systemctl restart sshd"
echo ""
echo "# Check SSH service status"
echo "systemctl status sshd"
echo ""
echo "# View SSH logs in real-time"
echo "journalctl -u sshd -f"
echo ""
echo "# Allow SSH through firewall"
echo "firewall-cmd --permanent --add-service=ssh"
echo "firewall-cmd --reload"
echo ""
echo "# Test SSH config"
echo "sshd -t"
echo ""
echo "# Generate missing host keys"
echo "ssh-keygen -A"
echo ""
echo "# Fix SELinux contexts (if SELinux is enforcing)"
echo "restorecon -Rv /etc/ssh/"
echo "restorecon -Rv ~/.ssh/"
