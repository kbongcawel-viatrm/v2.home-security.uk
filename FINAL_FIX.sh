#!/bin/bash
# FINAL_FIX.sh - Must be run as root
# This removes the :ro flag from the Suricata log mount

set -e

echo "============================================================"
echo "FINAL_FIX.sh - Remove :ro flag from Suricata log mount"
echo "============================================================"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "❌ ERROR: This script must be run as root"
    echo ""
    echo "Please run:"
    echo "  sudo $0"
    echo ""
    exit 1
fi

echo "✅ Running as root"
echo ""

echo "Step 1: Stop Fluent Bit container"
echo "------------------------------------------------------------"
podman stop fluent-bit 2>/dev/null || true
echo "✅ Container stopped"
echo ""

echo "Step 2: Find and modify the compose file"
echo "------------------------------------------------------------"
COMPOSE_FILE=""

# Try to find the compose file
if [ -f "/var/home/kb/workspace/home-security/v2.home-security.uk/compose.yaml" ]; then
    COMPOSE_FILE="/var/home/kb/workspace/home-security/v2.home-security.uk/compose.yaml"
    echo "Found compose file: $COMPOSE_FILE"
elif [ -f "/home/kb/workspace/home-security/v2.home-security.uk/compose.yaml" ]; then
    COMPOSE_FILE="/home/kb/workspace/home-security/v2.home-security.uk/compose.yaml"
    echo "Found compose file: $COMPOSE_FILE"
else
    echo "❌ ERROR: Cannot find compose.yaml"
    echo ""
    echo "Searching for compose files..."
    find /var/home/kb/workspace -name "compose.yaml" -type f 2>/dev/null | head -5
    exit 1
fi

echo ""
echo "Step 3: Backup original file"
echo "------------------------------------------------------------"
cp "$COMPOSE_FILE" "${COMPOSE_FILE}.backup"
echo "✅ Backup created: ${COMPOSE_FILE}.backup"
echo ""

echo "Step 4: Remove :ro flag from Suricata mount"
echo "------------------------------------------------------------"
# Use sed to remove :ro from the Suricata mount line
sed -i 's|/var/log/suricata:/var/log/suricata:ro|/var/log/suricata:/var/log/suricata|g' "$COMPOSE_FILE"

# Verify the change
if grep -q "/var/log/suricata:/var/log/suricata:ro" "$COMPOSE_FILE"; then
    echo "❌ ERROR: Failed to remove :ro flag"
    exit 1
else
    echo "✅ :ro flag removed successfully"
fi

echo ""
echo "Step 5: Show the modified section"
echo "------------------------------------------------------------"
grep -B 2 -A 2 "/var/log/suricata" "$COMPOSE_FILE" | head -10
echo ""

echo "Step 6: Restart Fluent Bit with new mount"
echo "------------------------------------------------------------"
podman start fluent-bit
sleep 5
echo "✅ Container restarted"
echo ""

echo "Step 7: Verify no more errors"
echo "------------------------------------------------------------"
sleep 10
ERRORS=$(podman logs fluent-bit 2>&1 | grep -c "cannot open /var/log/suricata/eve.json" || echo "0")

if [ "$ERRORS" -eq 0 ]; then
    echo "✅ SUCCESS: No more 'cannot open' errors!"
    echo ""
    echo "Container is now able to read /var/log/suricata/eve.json"
else
    echo "⚠️  Still seeing $ERRORS errors (may need to wait longer)"
fi

echo ""
echo "============================================================"
echo "Fix Complete!"
echo "============================================================"
echo ""
echo "To revert: cp ${COMPOSE_FILE}.backup ${COMPOSE_FILE}"
echo ""
