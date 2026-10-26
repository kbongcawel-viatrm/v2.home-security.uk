#!/usr/bin/env bash

SOURCE_DIR="/var/log/suricata/*"
DEST_DIR="/var/log/suricata-export"

while true; do
    cp -r "$SOURCE" "$DEST_DIR/"
    sleep 5
done
