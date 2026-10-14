#!/bin/bash
echo "Enabling podman commands inside toolbox..."
export CONTAINER_HOST="unix:///run/host$XDG_RUNTIME_DIR/podman/podman.sock"
podman --remote info
podman --remote -v
echo "Done."

