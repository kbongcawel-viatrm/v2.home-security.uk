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

# Initial synchronization
rsync -a "$SOURCE/" "$DEST/"
rsync -a "$SOURCE2/" "$DEST/"
rsync -a "$SOURCE3/" "$DEST/"

# Watch for changes recursively and synchronize after events
#while inotifywait -q -r \
#    -e close_write,create,delete,move \
#    "$SOURCE"; do
#    rsync -a "$SOURCE/" "$DEST/"
#done
while true; do
    rsync -a "$SOURCE/" "$DEST/"
    rsync -a "$SOURCE2/" "$DEST/"
    rsync -a "$SOURCE3/" "$DEST/"
    chown suricata:wheel -R $DEST/
    chmod 777 -R $DEST/
    sleep 5
done
