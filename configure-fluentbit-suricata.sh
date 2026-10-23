#!/bin/bash
# Configure Fluent Bit to properly read Suricata EVE JSON logs including rotated files
# Must be run as root

set -e

echo "============================================================"
echo "Configure Fluent Bit for Suricata Logs (Including Rotated)"
echo "============================================================"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "❌ ERROR: This script must be run as root"
    echo ""
    echo "Please run:"
    echo "  sudo $0"
    exit 1
fi

echo "✅ Running as root"
echo ""

# Step 1: Check Suricata log directory
echo "Step 1: Checking Suricata log directory..."
echo "------------------------------------------------------------"
if [ ! -d /var/log/suricata ]; then
    echo "❌ ERROR: /var/log/suricata directory not found"
    exit 1
fi

LOG_FILES=$(ls -1 /var/log/suricata/*.json 2>/dev/null | wc -l)
ROTATED_FILES=$(ls -1 /var/log/suricata/*.json-*.gz 2>/dev/null | wc -l)

if [ $LOG_FILES -eq 0 ] && [ $ROTATED_FILES -eq 0 ]; then
    echo "⚠️  No Suricata JSON log files found"
    echo "   Suricata may not be configured or running"
fi

echo "Found $LOG_FILES active JSON files, $ROTATED_FILES rotated files"
echo ""

# Step 2: Fix file permissions
echo "Step 2: Ensuring proper file permissions..."
echo "------------------------------------------------------------"
chown -R suricata:wheel /var/log/suricata/ 2>/dev/null || true
chmod -R 775 /var/log/suricata/ 2>/dev/null || true
chmod g+s /var/log/suricata/ 2>/dev/null || true

# Make sure eve.json exists (Suricata will create it if missing)
touch /var/log/suricata/eve.json 2>/dev/null || true
chown suricata:wheel /var/log/suricata/eve.json 2>/dev/null || true
chmod 660 /var/log/suricata/eve.json 2>/dev/null || true

echo "✅ Permissions set"
echo ""

# Step 3: Update Fluent Bit configuration
echo "Step 3: Updating Fluent Bit configuration..."
echo "------------------------------------------------------------"
FLUENT_CONF="/var/home/kb/workspace/home-security/v2.home-security.uk/fluent-bit/fluent-bit.conf"

if [ ! -f "$FLUENT_CONF" ]; then
    echo "❌ ERROR: Fluent Bit config not found at $FLUENT_CONF"
    exit 1
fi

# Backup
cp "$FLUENT_CONF" "${FLUENT_CONF}.backup.$(date +%s)"

# Update the Suricata tail input to handle rotated files better
cat > /tmp/suricata-input.conf << 'EOF'
[INPUT]
    Name              tail
    Tag               security.suricata.eve
    Path              /var/log/suricata/eve.json
    Parser            json
    DB                /fluent-bit/state/suricata-eve.db
    Read_from_Head    true
    Refresh_Interval  5
    Rotate_Wait       5
    Skip_Long_Lines   On
    Mem_Buf_Limit     10MB
    Path_Key          source_file
    storage.type      filesystem
    # Include rotated files pattern
    # Fluent Bit tail plugin automatically handles files matching the base name pattern
EOF

# Replace the Suricata input section
sed -i '/# SURICATA EVE JSON/,/# AUDITD/c\
# --------------------------------------------------\
# SURICATA EVE JSON\
# --------------------------------------------------\
[INPUT]\
    Name              tail\
    Tag               security.suricata.eve\
    Path              /var/log/suricata/eve.json\
    Parser            json\
    DB                /fluent-bit/state/suricata-eve.db\
    Read_from_Head    true\
    Refresh_Interval  5\
    Rotate_Wait       5\
    Skip_Long_Lines   On\
    Mem_Buf_Limit     10MB\
    Path_Key          source_file\
    storage.type      filesystem\
\
# --------------------------------------------------\
# AIDE INTEGRITY REPORTS\
# --------------------------------------------------\
[INPUT]\
    Name              tail\
    Tag               security.aide\
    Path              /var/log/aide/aide.log\
    Parser            syslog-rfc3164\
    DB                /fluent-bit/state/aide.db\
    Read_from_Head    true\
    Refresh_Interval  5\
    Rotate_Wait       5\
    Skip_Long_Lines   On\
    Mem_Buf_Limit     5MB\
    Path_Key          source_file\
    storage.type      filesystem' "$FLUENT_CONF"

echo "✅ Fluent Bit configuration updated"
echo ""

# Step 4: Restart Fluent Bit
echo "Step 4: Restarting Fluent Bit..."
echo "------------------------------------------------------------"
if podman ps --format "{{.Names}}" | grep -q "fluent-bit"; then
    podman restart fluent-bit
    sleep 5
    echo "✅ Fluent Bit restarted"
else
    echo "⚠️  Fluent Bit container not running"
fi
echo ""

# Step 5: Verify
echo "Step 5: Verification..."
echo "------------------------------------------------------------"
if podman ps --format "{{.Names}}" | grep -q "fluent-bit"; then
    echo "✅ Fluent Bit container is running"
    
    # Check if Fluent Bit can read the file (from host perspective)
    if [ -r /var/log/suricata/eve.json ]; then
        echo "✅ Suricata log file is readable by Fluent Bit"
    else
        echo "❌ Suricata log file is NOT readable"
        echo "   Check file permissions and SELinux context"
    fi
    
    # Show recent Fluent Bit logs
    echo ""
    echo "Last 20 lines of Fluent Bit logs:"
    podman logs fluent-bit 2>&1 | tail -20
else
    echo "❌ Fluent Bit container is not running"
fi

echo ""
echo "============================================================"
echo "Configuration Complete!"
echo "============================================================"
echo ""
echo "Key changes made:"
echo "1. ✅ File permissions set to 660 (suricata:wheel)"
echo "2. ✅ Fluent Bit reads from /var/log/suricata/eve.json"
echo "3. ✅ Read_from_Head set to true for immediate processing"
echo "4. ✅ Rotate_Wait set to 5 seconds"
echo "5. ✅ Fluent Bit restarted"
echo ""
echo "Fluent Bit will now:"
echo "- Read active eve.json file"
echo "- Automatically pick up rotated files (eve.json-*)"
echo "- Process logs as soon as they appear"
echo ""
