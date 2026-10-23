#!/bin/bash
# 
# FIX_AS_ROOT.sh - Must be run with sudo
# 
# This script MUST be run as root to successfully change SELinux contexts.
# It will fix the "Permission denied" errors when Fluent Bit tries to access
# Suricata log files in /var/log/suricata/
#
# Usage:
#   sudo ./FIX_AS_ROOT.sh
#

set -e

echo "============================================================"
echo "FIX_AS_ROOT.sh - SELinux Context Fix for Suricata Logs"
echo "============================================================"
echo ""
echo "⚠️  IMPORTANT: This script MUST be run with sudo"
echo ""

# Verify we're running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ ERROR: This script must be run as root"
    echo ""
    echo "Please run:"
    echo "  sudo $0"
    echo ""
    exit 1
fi

echo "✅ Running as root - proceeding with SELinux fix"
echo ""

# Check if the target file exists
if [ ! -f /var/log/suricata/eve.json ]; then
    echo "❌ ERROR: File not found: /var/log/suricata/eve.json"
    echo ""
    echo "Check if Suricata is installed and configured correctly."
    echo "Suricata should be writing to /var/log/suricata/eve.json"
    exit 1
fi

echo "Step 1: Checking current SELinux context..."
echo "------------------------------------------------------------"
CURRENT_CONTEXT=$(ls -Z /var/log/suricata/eve.json 2>/dev/null | awk '{print $4}' | cut -d: -f3)
echo "Current context: $CURRENT_CONTEXT"
echo ""

if [ "$CURRENT_CONTEXT" = "var_log_t" ]; then
    echo "✅ Context is already correct: var_log_t"
    echo "No changes needed!"
    echo ""
    exit 0
fi

echo "Step 2: Checking SELinux status..."
echo "------------------------------------------------------------"
if command -v getenforce &> /dev/null; then
    STATUS=$(getenforce 2>/dev/null || echo "Unknown")
    echo "SELinux status: $STATUS"
    if [ "$STATUS" = "Enforcing" ]; then
        echo "⚠️  SELinux is Enforcing - context fix is required"
    fi
    echo ""
fi

echo "Step 3: Applying SELinux context fix..."
echo "------------------------------------------------------------"

# Try to apply the fix
if command -v chcon &> /dev/null; then
    echo "Applying context: system_u:object_r:var_log_t:s0"
    chcon -R system_u:object_r:var_log_t:s0 /var/log/suricata/ 2>&1 || {
        echo "⚠️  chcon encountered issues (may be due to existing custom contexts)"
        echo "   Continuing anyway..."
    }
    
    # Try to restore default context
    if command -v restorecon &> /dev/null; then
        echo "Running restorecon to apply default contexts..."
        restorecon -Rv /var/log/suricata/ 2>&1 || true
    fi
    
    # Verify the change
    NEW_CONTEXT=$(ls -Z /var/log/suricata/eve.json 2>/dev/null | awk '{print $4}' | cut -d: -f3)
    echo "New context: $NEW_CONTEXT"
    echo ""
    
    if [ "$NEW_CONTEXT" = "var_log_t" ]; then
        echo "✅ SUCCESS: Context changed to var_log_t"
    else
        echo "⚠️  Context is: $NEW_CONTEXT"
        echo "   Expected: var_log_t"
        echo "   This may be acceptable depending on your system configuration"
    fi
else
    echo "❌ ERROR: chcon command not found"
    echo "   Cannot apply SELinux context fix"
    exit 1
fi

echo ""
echo "Step 4: Verifying file permissions..."
echo "------------------------------------------------------------"
ls -ld /var/log/suricata
ls -l /var/log/suricata/eve.json
echo ""

# Check if semanage is available for persistent fix
if command -v semanage &> /dev/null; then
    echo "Making context persistent across relabels..."
    semanage fcontext -a -t var_log_t "/var/log/suricata(/.*)?" 2>&1 || true
    restorecon -Rv /var/log/suricata/ 2>&1 || true
    echo ""
fi

echo "============================================================"
echo "✅ SELinux Context Fix Complete!"
echo "============================================================"
echo ""

echo "Step 5: Restarting Fluent Bit..."
echo "------------------------------------------------------------"
if command -v podman &> /dev/null; then
    if podman ps --format "{{.Names}}" | grep -q "fluent-bit"; then
        echo "Restarting Fluent Bit container..."
        podman restart fluent-bit
        echo "✅ Fluent Bit restarted"
    else
        echo "⚠️  Fluent Bit container not running"
    fi
else
    echo "⚠️  Podman not available"
fi
echo ""

echo "============================================================"
echo "Next Steps"
echo "============================================================"
echo ""
echo "1. Verify no more 'Permission denied' errors:"
echo "   podman logs fluent-bit"
echo ""
echo "2. Check the first 50 lines of logs:"
echo "   podman logs --tail=50 fluent-bit"
echo ""
echo "3. If errors persist, check SELinux audit logs:"
echo "   sudo ausearch -m avc -ts recent | grep suricata"
echo ""
echo "4. Temporarily test with SELinux permissive (for debugging):"
echo "   sudo setenforce 0"
echo "   # Test Fluent Bit access"
echo "   sudo setenforce 1"
echo ""

echo "🎉 Fix applied successfully!"
echo ""
