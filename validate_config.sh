#!/bin/bash
# Fluent Bit Configuration Validator
# Validates the Fluent Bit configuration files

set -e

CONFIG_FILE="/var/home/kb/workspace/home-security/fluent-bit.conf"
PARSERS_FILE="/var/home/kb/workspace/home-security/parsers.conf"

# Check if files exist
if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Configuration file not found: $CONFIG_FILE"
    exit 1
fi

if [ ! -f "$PARSERS_FILE" ]; then
    echo "ERROR: Parsers file not found: $PARSERS_FILE"
    exit 1
fi

echo "✓ Configuration files found"

# Check basic syntax (section headers)
CONFIG_SECTIONS=$(grep -E '^\[.*\]' "$CONFIG_FILE" | sort -u)
PARSERS_SECTIONS=$(grep -E '^\[.*\]' "$PARSERS_FILE" | sort -u)

echo "✓ Configuration sections found in fluent-bit.conf:"
echo "$CONFIG_SECTIONS" | sed 's/^/  - /'

echo "✓ Parser sections found in parsers.conf:"
echo "$PARSERS_SECTIONS" | sed 's/^/  - /'

# Check for required sections
if ! echo "$CONFIG_SECTIONS" | grep -q "\[SERVICE\]"; then
    echo "ERROR: Missing [SERVICE] section in fluent-bit.conf"
    exit 1
fi

if ! echo "$CONFIG_SECTIONS" | grep -q "\[INPUT\]"; then
    echo "ERROR: Missing [INPUT] section in fluent-bit.conf"
    exit 1
fi

if ! echo "$CONFIG_SECTIONS" | grep -q "\[FILTER\]"; then
    echo "WARNING: No [FILTER] section found in fluent-bit.conf (optional)"
fi

if ! echo "$CONFIG_SECTIONS" | grep -q "\[OUTPUT\]"; then
    echo "ERROR: Missing [OUTPUT] section in fluent-bit.conf"
    exit 1
fi

echo "✓ All required sections present"

# Check for required inputs
INPUT_COUNT=$(grep -c "^\[INPUT\]" "$CONFIG_FILE" || true)
echo "✓ Found $INPUT_COUNT input configurations"

if [ "$INPUT_COUNT" -lt 6 ]; then
    echo "WARNING: Expected at least 6 input configurations, found $INPUT_COUNT"
fi

# Check parser references
if grep -q "parsers_file" "$CONFIG_FILE"; then
    echo "✓ Parsers file is referenced in configuration"
else
    echo "WARNING: parsers_file directive not found in [SERVICE] section"
fi

# Validate parser names are referenced
PARSER_NAMES=$(grep "^\[PARSER\]" -A 1 "$PARSERS_FILE" | grep "Name" | awk '{print $3}' | sort -u)
echo "✓ Parsers defined: $PARSER_NAMES"

# Check for critical configuration options
if grep -q "file_rotated_logs on" "$CONFIG_FILE"; then
    echo "✓ Rotated log handling enabled"
else
    echo "WARNING: file_rotated_logs option not found"
fi

if grep -q "storage.path" "$CONFIG_FILE"; then
    echo "✓ Storage path configured"
else
    echo "WARNING: storage.path not configured"
fi

if grep -q "Read_From_Tail On" "$CONFIG_FILE"; then
    echo "✓ Read from tail enabled for systemd inputs"
else
    echo "WARNING: Read_From_Tail not enabled"
fi

echo ""
echo "=== Configuration Summary ==="
echo "Config file: $CONFIG_FILE"
echo "Parsers file: $PARSERS_FILE"
echo "Total sections: $(echo "$CONFIG_SECTIONS" | wc -l)"
echo "Total parsers: $(echo "$PARSERS_SECTIONS" | wc -l)"
echo ""
echo "✓ Configuration validation complete!"
echo ""
echo "Next steps:"
echo "1. Review the configuration files"
echo "2. Update output destinations as needed"
echo "3. Test with: fluent-bit -c $CONFIG_FILE -i debug"
echo "4. Deploy to production"
