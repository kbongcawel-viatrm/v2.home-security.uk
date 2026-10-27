# Worker Image

This directory contains the Dockerfile for the shared worker image used by both the `security-ai` and `ansible-ai` containers in the home-security stack.

## Overview

The worker image is a Python 3.12 slim-based image that bundles both AI worker applications:

- **security-ai** (`/app/security-ai/`) — Queries OpenObserve for security logs, sends them to Ollama for analysis, and writes review-only draft artifacts.
- **ansible-ai** (`/app/ansible-ai/`) — Watches the security-ai manifest and generates deterministic, draft-only Ansible playbooks.

Both workers run as a non-root user (`app`, UID/GID 10001) and share the same base image to minimize resource usage.

## Image Details

| Attribute | Value |
|---|---|
| Base image | `docker.io/library/python:3.12-slim` |
| Runtime user | `app` (UID 10001, GID 10001) |
| Working directory | `/app` |
| Python packages | `openobserve-telemetry-sdk`, `PyYAML` |
| Entrypoint | `python` (command is provided by Compose) |

## Building from Scratch

The Dockerfile uses the **project root** as the build context because it copies source directories (`security-ai/` and `ansible-ai/`) from the repository root.

### Prerequisites

- [Podman](https://podman.io/) (rootless) or Docker installed and running
- Access to `docker.io/library/python:3.12-slim` (pulled automatically on first build)

### Build Commands

From the **project root** (`v2.home-security.uk/`):

```bash
# Build and tag as a local image
podman build -f worker-image/Dockerfile -t demo.goharbor.io/home-security-uk/worker-template:1.3 .

# Verify the image was created
podman images | grep worker-template

# Inspect the image
podman inspect demo.goharbor.io/home-security-uk/worker-template:1.3 --format '{{.Config.User}} {{.Config.WorkingDir}} {{.Config.Entrypoint}}'
```

With Docker:

```bash
docker build -f worker-image/Dockerfile -t demo.goharbor.io/home-security-uk/worker-template:1.3 .
docker images | grep worker-template
```

### Build Options

| Option | Description |
|---|---|
| `--no-cache` | Force a full rebuild, ignoring cached layers |
| `--layers` | Use intermediate layer caching (default with BuildKit) |
| `--build-arg` | Pass build-time variables (none currently defined) |
| `-t <name>:<tag>` | Tag the resulting image |

Example with no cache:

```bash
podman build --no-cache -f worker-image/Dockerfile -t demo.goharbor.io/home-security-uk/worker-template:1.3 .
```

## Versioning

The image is tagged with semantic versioning:

| Tag | Description |
|---|---|
| `1.2` | Original worker image (Suricata EVE/text, auditd, AIDE, host journal) |
| `1.3` | Added support for Suricata `fast.log`, ClamAV scan logs (`clamav-scan.log`, `clamav-secureblue-scan.log`) |

To release a new version:

1. Update `security-ai/worker.py`, `ansible-ai/worker.py`, or other source files as needed.
2. Bump the image tag in `compose.yaml` (both `security-ai` and `ansible-ai` services).
3. Rebuild and tag:

   ```bash
   podman build -f worker-image/Dockerfile -t demo.goharbor.io/home-security-uk/worker-template:<new-version> .
   ```

4. Recreate the worker containers:

   ```bash
   podman compose up -d --no-deps --force-recreate security-ai ansible-ai
   ```

## Pushing to a Registry

If you need to push the image to a remote registry (e.g., Harbor at `demo.goharbor.io`):

```bash
# Login to the registry
podman login demo.goharbor.io

# Tag for the remote registry (if not already tagged)
podman tag demo.goharbor.io/home-security-uk/worker-template:1.3 demo.goharbor.io/home-security-uk/worker-template:1.3

# Push
podman push demo.goharbor.io/home-security-uk/worker-template:1.3
```

> **Note:** The Compose file uses `pull_policy: never`, so the image must exist locally. If you push to a remote registry and want to use the remote image, change `pull_policy` to `always` or remove it.

## Directory Structure

```
worker-image/
├── Dockerfile          # Image definition (build context: project root)
├── .gitignore          # Excludes Python caches, build artifacts, secrets
└── README.md           # This file
```

## Build Context

The Dockerfile expects the following directories to exist in the build context (project root):

```
v2.home-security.uk/
├── security-ai/        # Copied to /app/security-ai/ in the image
│   ├── worker.py
│   ├── artifact_writer.py
│   ├── source_catalog.py
│   └── session_forensics_skill.md
├── ansible-ai/         # Copied to /app/ansible-ai/ in the image
│   ├── worker.py
│   └── playbook_generator.py
└── worker-image/
    └── Dockerfile      # Build instructions
```

## Troubleshooting

### Build fails with "COPY failed: no such file or directory"

Ensure you are running the build from the **project root**, not from the `worker-image/` directory:

```bash
# Correct — run from project root
cd /var/home/kb/workspace/home-security/v2.home-security.uk
podman build -f worker-image/Dockerfile -t demo.goharbor.io/home-security-uk/worker-template:1.3 .

# Incorrect — will fail because security-ai/ and ansible-ai/ are not in worker-image/
cd worker-image
podman build -t demo.goharbor.io/home-security-uk/worker-template:1.3 .
```

### Image is large

The image is approximately 191 MB. To reduce size:

- Use `--no-cache` during build to avoid caching pip downloads in layers (already uses `--no-cache-dir` for pip)
- Consider a multi-stage build if build-time dependencies are added in the future

### Container fails to start with permission errors

The image runs as UID 10001 (`app`). Ensure mounted volumes are writable by this user:

```bash
# Check volume ownership
podman volume inspect v2home-securityuk_security_ai_state --format '{{.Mountpoint}}'
ls -la /var/home/kb/.local/share/containers/storage/volumes/v2home-securityuk_security_ai_state/_data
```

With rootless Podman and `userns_mode: keep-id:uid=10001,gid=10001`, the container user maps to the host user. Ensure the host user owns the mounted directories.
