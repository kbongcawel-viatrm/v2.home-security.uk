<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=07111f&height=190&section=header&text=HOME%20SECURITY%20AI&fontSize=42&fontColor=edf5fa&fontAlignY=42&desc=VISIBILITY.%20CONTEXT.%20CONTROL.&descSize=14&descColor=4ce0b3&animation=fadeIn" width="100%" alt="Home Security AI — Visibility. Context. Control.">

<p><strong>A local-first security observability lab for your home network.</strong></p>

<p>
<a href="https://github.com/kbongcawel-viatrm/v2.home-security.uk"><img src="https://img.shields.io/badge/Repository-v2.home--security.uk-4ce0b3?style=flat-square&logo=github&logoColor=07111f" alt="Repository"></a>
<img src="https://img.shields.io/badge/Runtime-Podman-8b83ff?style=flat-square&logo=podman&logoColor=white" alt="Podman">
<img src="https://img.shields.io/badge/AI-Ollama-63c8e9?style=flat-square" alt="Ollama">
<img src="https://img.shields.io/badge/Focus-Security%20Observability-f6c66f?style=flat-square" alt="Security observability">
</p>
</div>

---

## Overview

Home Security AI combines network and host telemetry, searchable observability, and local LLM analysis. It is designed to make security events easier to understand while keeping proposed changes under administrator control.

## Platform at a glance

| Layer | Components | Purpose |
|---|---|---|
| Detection | Suricata, journald, auditd, AIDE | Network, host and integrity signals |
| Collection | Fluent Bit | Normalize and forward events |
| Observability | OpenObserve, Prometheus | Search, dashboards, metrics and traces |
| Intelligence | Ollama, security-ai | Analyze bounded event batches and create recommendations |
| Change workflow | ansible-ai, Ansible | Prepare policy-validated drafts for review |

## Event flow

<div align="center">
<img src="https://capsule-render.vercel.app/api?type=transparent&color=0:07111f,100:0c2b35&height=95&section=header&text=COLLECT%20%E2%86%92%20OBSERVE%20%E2%86%92%20ANALYZE%20%E2%86%92%20REVIEW&fontSize=17&fontColor=4ce0b3" width="100%" alt="Collect, observe, analyze, review">
</div>

1. **Collect** — Suricata and host sources emit network and system events.
2. **Forward** — Fluent Bit routes records into OpenObserve `security_logs`.
3. **Analyze** — `security-ai` queries bounded, deduplicated batches and sends relevant evidence to local Ollama.
4. **Review** — Findings and proposed rule/configuration drafts are stored for human assessment.
5. **Approve** — Reviewed artifacts can enter a separately controlled validation and deployment workflow.

## Observability

- **OpenObserve** — local log search, dashboards, AI recommendations and inference traces (`127.0.0.1:5080`).
- **Prometheus** — self-scraped metrics with remote-write to OpenObserve (`127.0.0.1:9090`).
- **Ollama** — internal-only local inference endpoint; not published on the host.

The dashboard documentation covers security logs, metrics and AI recommendations. Some AI panels require at least one successful worker analysis before data appears.

## Safety model

The AI worker creates recommendations; it does not directly change live security rules or execute response actions. Generated artifacts and playbooks require review, validation and explicit approval. Firewalld drafts remain inert until an administrator deliberately applies an approved change.

## Repository layout

```text
.
├── v2.home-security.uk/   # Security stack, workers, scripts and documentation
├── homepage/              # Project landing page (HTML, CSS and JavaScript)
└── README.md              # Project overview
```

## Documentation

| Guide | Summary |
|---|---|
| [Stack architecture](v2.home-security.uk/docs/STACK.md) | Services, event pipeline, AI handoff, deployment boundaries and operations |
| [Dashboards](v2.home-security.uk/docs/DASHBOARDS.md) | OpenObserve dashboards and data views |
| [Prometheus](v2.home-security.uk/docs/PROMETHEUS.md) | Metrics endpoints and OpenObserve remote-write |
| [AI rule generation](v2.home-security.uk/docs/LLM_RULE_GENERATION.md) | Generated Suricata and firewall rule drafts |
| [AI observability](v2.home-security.uk/docs/SECURITY_AI_OBSERVABILITY.md) | Ollama inference tracing and privacy |
| [Podman / Toolbox](v2.home-security.uk/docs/PODMAN-TOOLBOX-FIX.md) | Host-aware Podman wrapper approach |

## Quick access

| Service | Local URL |
|---|---|
| OpenObserve | [http://127.0.0.1:5080](http://127.0.0.1:5080) |
| Prometheus | [http://127.0.0.1:9090](http://127.0.0.1:9090) |

These services are bound to loopback by default and are intended for local access.

## Landing page

Open `homepage/index.html` locally, or serve the folder with any static web server. See [homepage/README.md](homepage/README.md) for details.

## Project status

This repository documents an evolving home-lab implementation. Service availability, ingested data and dashboard content depend on the host configuration and successful stack operation. Refer to the stack guide for current prerequisites and limitations.

<div align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&color=07111f&height=85&section=footer&text=LOCAL-FIRST%20%E2%80%A2%20OPEN%20TOOLS%20%E2%80%A2%20HUMAN%20CONTROL&fontSize=13&fontColor=4ce0b3" width="100%" alt="Local-first, open tools, human control">
</div>