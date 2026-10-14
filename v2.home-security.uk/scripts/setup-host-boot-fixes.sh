#!/usr/bin/env bash
# One-time host fixes that must survive reboots on this rpm-ostree
# (Secureblue) system. Covers:
#   1. /var/log/suricata ownership survives tmpfiles resets at boot
#      (rpm-ostree-autovar.conf otherwise resets it to suricata:suricata 0750,
#      which breaks both Suricata's log files and the rootless Podman
#      bind-mount relabel used by fluent-bit's ":z" mounts)
#   2. rootless Podman stack auto-starts at boot (user lingering)
#   3. stable names for the USB NICs whose kernel names shuffle each boot
#
# Usage (from the repo, as root):
#   sudo ./scripts/setup-host-boot-fixes.sh
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_USER="${SUDO_USER:-kbongcawel}"
# Log-directory group: wheel. wheel members (including the suricata service
# user, ensured below) get shared access via the group. Ownership stays with
# $TARGET_USER because Podman's ":z" relabel checks ownership, not group.
TARGET_GROUP=wheel

# 1. Durable /var/log/suricata ownership: mask rpm-ostree's tmpfiles entry
#    (a same-named file in /etc masks the /usr/lib one) and hand the directory
#    to the rootless Podman user so ":z" relabeling works on every boot.
TMP_SRC=/usr/lib/tmpfiles.d/rpm-ostree-autovar.conf
TMP_DST=/etc/tmpfiles.d/rpm-ostree-autovar.conf
install -Dm644 "$TMP_SRC" "$TMP_DST"
sed -i 's|^d /var/log/suricata 0750 suricata suricata - -$|d /var/log/suricata 2770 '"$TARGET_USER"' '"$TARGET_GROUP"' - -|' "$TMP_DST"
grep -qE "^d /var/log/suricata 2770 $TARGET_USER $TARGET_GROUP" "$TMP_DST" || {
    echo "ERROR: failed to override the /var/log/suricata tmpfiles line" >&2
    exit 1
}

# 2. Repair current state immediately (tmpfiles only re-runs at boot).
#    Owner stays $TARGET_USER (Podman needs ownership for the ":z" relabel);
#    group is $TARGET_GROUP so wheel members, including the suricata user,
#    share access. Suricata itself runs unconfined.
chown -R "$TARGET_USER:$TARGET_GROUP" /var/log/suricata
chmod -R u+rwX,g+rwX,o-rwx /var/log/suricata
chmod 2770 /var/log/suricata   # setgid: newly created log files inherit wheel

# 3. Linger so rootless Podman (and the compose stack) survives reboots.
loginctl enable-linger "$TARGET_USER"

# 3b. Ensure the suricata service user carries the $TARGET_GROUP membership
#     (part of the shared-access scheme for /var/log/suricata).
if id suricata &>/dev/null; then
    usermod -aG "$TARGET_GROUP" suricata
fi

# 4. Stable names for the USB NICs (match on permanent MAC).
install -Dm644 "$PROJECT_ROOT/scripts/systemd/network/10-sec-workstation.link" \
    /etc/systemd/network/10-sec-workstation.link
install -Dm644 "$PROJECT_ROOT/scripts/systemd/network/11-sec-lan2.link" \
    /etc/systemd/network/11-sec-lan2.link

# 5. Restart Suricata so it reopens its log files with the fixed permissions.
systemctl restart suricata

echo "OK: tmpfiles override, ownership, linger, and stable NIC names applied."
echo "Reboot to apply the stable NIC names (sec-workstation, sec-lan2)."
