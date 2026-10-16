# Fixing Podman inside Toolbox: Complete Solution

## The Problem

When running Podman inside a Toolbox container, you get this error:

```
Error: fatal error, invalid internal status, unable to create a new pause process:
cannot re-exec process to join the existing user namespace. Try running
"podman system migrate" and if that doesn't work reboot to recover
```

### Root Cause

```
Toolbox Container
└── User Namespace (created by Toolbox for isolation)
    └── Podman Process (rootless mode)
        └── Tries to create ANOTHER user namespace
            └── ❌ FAILS: Nested user namespaces not allowed
```

Toolbox creates a user namespace for container isolation. When Podman runs in
rootless mode (the default), it also tries to create a user namespace. Linux
does not allow nested user namespaces in this way, causing the error.

### Why Pods Don't Solve This

Using `podman pod` does NOT solve this issue because:
- Pods share namespaces **between containers** in the pod
- But Podman **itself** still needs to create a user namespace for rootless mode
- That namespace creation still conflicts with Toolbox's namespace

The issue is at the **Podman level**, not the **container level**.

---

## The Solution

**Never run Podman directly inside Toolbox. Always run it on the host.**

We provide wrapper scripts that automatically detect if you're inside Toolbox
and route commands to the host via `flatpak-spawn --host`.

### Wrapper Scripts

| Script | Purpose |
|--------|---------|
| `scripts/podman-host.sh` | Drop-in replacement for `podman` |
| `scripts/podman-compose-host.sh` | Drop-in replacement for `podman-compose` |
| `scripts/host-exec.sh` | Low-level wrapper using `flatpak-spawn --host` |

### How It Works

```bash
#!/usr/bin/env bash
# scripts/podman-host.sh

if [[ -e /run/.toolboxenv ]]; then
    # Inside Toolbox - run on host
    exec ./scripts/host-exec.sh podman "$@"
else
    # Not in Toolbox - run directly
    exec podman "$@"
fi
```

```bash
#!/usr/bin/env bash
# scripts/host-exec.sh

if [[ -e /run/.toolboxenv ]]; then
    exec flatpak-spawn --host "$@"
else
    exec "$@"
fi
```

### Usage

**Instead of:**
```bash
podman ps                    # ❌ Fails inside Toolbox
podman-compose up -d         # ❌ Fails inside Toolbox
```

**Use:**
```bash
./scripts/podman-host.sh ps              # ✅ Works
./scripts/podman-compose-host.sh up -d   # ✅ Works
```

---

## GitHub Actions Workflow

The `deploy-v2-stack.yml` workflow uses these wrappers for all Podman operations:

```yaml
# Pull images
./scripts/host-exec.sh env -u CONTAINER_HOST podman pull ...

# Build image
./scripts/host-exec.sh env -u CONTAINER_HOST podman build ...

# Deploy with compose
./scripts/podman-compose-host.sh -f compose.yaml up -d --no-build

# Health checks
./scripts/podman-host.sh ps
./scripts/podman-host.sh inspect ...
./scripts/podman-host.sh logs ...
```

All Podman commands are routed through the wrappers, ensuring they run on the
host where the Podman socket is available.

---

## One-Time Fix (If Storage is Corrupted)

If you've been running Podman inside Toolbox and the storage is corrupted:

```bash
# On the HOST (not inside Toolbox)
flatpak-spawn --host podman system migrate

# Then reboot the host
sudo reboot
```

This migrates the Podman storage to a new format. However, the error may return
if you continue running Podman inside Toolbox. **Use the wrappers instead.**

---

## Manual Usage Inside Toolbox

For interactive use inside Toolbox:

```bash
# Add to ~/.bashrc or ~/.zshrc
alias podman='./scripts/podman-host.sh'
alias podman-compose='./scripts/podman-compose-host.sh'

# Or use full paths
/path/to/repo/v2.home-security.uk/scripts/podman-host.sh ps
```

---

## Verification

Test that the wrappers work:

```bash
# Should work (runs on host)
./scripts/podman-host.sh info
./scripts/podman-host.sh ps

# Should also work
./scripts/podman-compose-host.sh --version
```

---

## Summary

| Approach | Works? | Notes |
|----------|--------|-------|
| `podman system migrate` | ⚠️ Temporary | Fixes storage, error may return |
| Reboot host | ⚠️ Temporary | Clears state, error may return |
| Use podman pods | ❌ No | Doesn't solve root cause |
| **Use wrapper scripts** | ✅ **Yes** | **Permanent solution** |
| Run runner outside Toolbox | ✅ Yes | Alternative, more complex |

**The wrapper scripts are the permanent solution.** They ensure Podman always
runs on the host, completely eliminating the nested user namespace issue.
