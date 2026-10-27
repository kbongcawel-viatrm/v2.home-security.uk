#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE="/var/log/suricata"
SOURCE2="/var/log/aide/"
SOURCE3="/var/log/audit/"
DEST="/var/log/suricata-export"


if [[ $EUID -ne 0 ]]; then
    echo "Run this script as root." >&2
    exit 1
fi

for cmd in inotifywait rsync; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "Missing dependency: $cmd" >&2
        exit 1
    }
done

mkdir -p "$DEST"

secure_export_permissions() {
    # Rootless Podman maps Fluent Bit's container root to the invoking host
    # user (kb). Grant that identity read/list access without making copied
    # security logs world-readable or world-writable.
    chown -R openobserve-agent:openobserve-agent "$DEST"
    find "$DEST" -type d -exec chmod 0750 {} +
    find "$DEST" -type f -exec chmod 0640 {} +
    find "$DEST" -type d -exec setfacl -m u:kb:rx {} +
    find "$DEST" -type f -exec setfacl -m u:kb:r-- {} +
}

# Initial synchronization
rsync -a "$SOURCE/" "$DEST/"
rsync -a "$SOURCE2/" "$DEST/"
rsync -a "$SOURCE3/" "$DEST/"
secure_export_permissions

while true; do
    rsync -a "$SOURCE/" "$DEST/"
    rsync -a "$SOURCE2/" "$DEST/"
    rsync -a "$SOURCE3/" "$DEST/"
    secure_export_permissions
    sleep 30
done

