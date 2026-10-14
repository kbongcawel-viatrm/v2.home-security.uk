#!/bin/bash

# Enables rootless Podman services/socket on the host and makes the
# rootless Podman socket usable from inside Toolbox containers.
# Run as your normal user (NOT root).
# Add these in the ~/.bashrc
# enable podman inside toolbox
# export CONTAINER_HOST="unix:///run/user/1000/podman/podman.sock"
# podman() { command podman --remote --url "unix:///run/user/1000/podman/podman.sock" "$@"; }"
#
#
set -u

MARK_BEGIN="# >>> rootless podman remote (managed by setup-rootless-podman.sh) >>>"
MARK_END="# <<< rootless podman remote (managed by setup-rootless-podman.sh) <<<"

if [ "$(id -u)" -eq 0 ]; then
    echo "Do not run this script as root. Run it as your normal user."
    exit 1
fi

SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"

# Step 1: Enable and start rootless podman.socket and podman.service
echo "Enabling and starting rootless podman.socket and podman.service..."
systemctl --user daemon-reload
if ! systemctl --user enable --now podman.socket; then
    echo "✗ Failed to enable/start rootless podman.socket"
    exit 1
fi
if ! systemctl --user enable --now podman.service; then
    echo "✗ Failed to enable/start rootless podman.service"
    exit 1
fi

# Step 2: Verify the rootless socket exists
for _ in 1 2 3 4 5; do
    [ -S "$SOCK" ] && break
    sleep 1
done
if [ -S "$SOCK" ]; then
    echo "✓ Rootless Podman socket is available at: $SOCK"
else
    echo "✗ Rootless Podman socket not found at: $SOCK"
    systemctl --user status podman.socket --no-pager || true
    exit 1
fi

# Step 3: Toolbox-specific setup (only when running inside a toolbox/container)
if [ -f /run/.containerenv ]; then
    echo "Detected container environment (Toolbox). Configuring Podman client..."

    if ! command -v podman-remote >/dev/null 2>&1 && ! command -v podman >/dev/null 2>&1; then
        echo "No Podman client in this container. Installing podman-remote..."
        if sudo dnf install -y podman-remote; then
            echo "✓ Installed podman-remote"
        else
            echo "✗ Could not install podman-remote (try: sudo dnf install -y podman-remote)"
            exit 1
        fi
    fi

    if command -v podman-remote >/dev/null 2>&1; then
        CLIENT="podman-remote"
    else
        CLIENT="podman"
    fi

    # Write the alias/function block into ~/.bashrc (idempotent, checked)
    BASHRC="$HOME/.bashrc"
    BLOCK="$MARK_BEGIN
export CONTAINER_HOST=\"unix://$SOCK\"
podman() { command $CLIENT --remote --url \"unix://$SOCK\" \"\$@\"; }
$MARK_END"
    if { grep -qF "$MARK_BEGIN" "$BASHRC" 2>/dev/null || true; } && grep -qF "$MARK_BEGIN" "$BASHRC" 2>/dev/null; then
        echo "✓ podman alias already present in $BASHRC"
    elif printf '\n%s\n' "$BLOCK" >> "$BASHRC" 2>/dev/null; then
        echo "✓ Added podman alias to $BASHRC (uses $CLIENT --remote --url unix://$SOCK)"
        echo "  Run 'source ~/.bashrc' or open a new toolbox shell to apply."
    else
        echo "✗ Could not write to $BASHRC (permission denied). Add these lines manually:"
        echo "$BLOCK"
    fi
else
    echo "Not inside a toolbox container; host services are configured."
    echo "Run this script from inside a toolbox to set up the Podman client there."
fi

echo ""
echo "Done. Verify with: systemctl --user status podman.socket"

