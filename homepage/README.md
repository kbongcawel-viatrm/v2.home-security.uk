# Home Security AI — Homepage

A responsive, static project landing page for the Home Security Stack. It uses the existing lightweight HTML, CSS and JavaScript implementation and is served as Cloudflare Worker static assets.

## Design direction

The page adapts the **Netic** design patterns from [ThemeWagon](https://themewagon.com/themes/netic/): sticky navigation, a strong hero header, service/feature cards, clear calls to action, responsive multi-section layout and concise footer navigation. The implementation is an original Home Security AI design; it does not bundle or copy Netic source code.

The visual identity is a dark, technical security-operations theme with mint/cyan highlights, subtle grid textures and compact monospace labels. The page is intentionally focused on platform architecture, event visibility, observability and human-reviewed automation.

## Content and diagrams

- `index.html` — page structure, metadata, navigation, feature content and architecture gallery.
- `styles.css` — responsive layout, typography, colors, cards, dashboard preview and diagram presentation.
- `script.js` — mobile navigation state and current-year footer.
- `assets/home-security-stack-banner.png` — platform banner.
- `assets/network-ai-flow.png` — network traffic, Suricata, Fluent Bit, OpenObserve, Ollama and response recommendation flow.
- `assets/cloudflare-aws-architecture.png` — Cloudflare edge, AWS architecture and CI/CD overview.
- `worker/index.js` — Worker entry point forwarding requests to static asset binding.

The dashboard panel is an illustrative UI preview, not live telemetry. OpenObserve and Prometheus links point to loopback addresses and therefore work only from the host where those services are running.

## Preview locally

From this directory:

```bash
python3 -m http.server 8080
```

Open [http://127.0.0.1:8080](http://127.0.0.1:8080).

## Deploy

The Cloudflare Worker configuration is in `wrangler.jsonc` and attaches the custom domain `v2.home-security.uk`. The GitHub Actions workflow at `.github/workflows/deploy-homepage.yml` runs on pushes to `main` that change `homepage/**`, and can also be started manually.

Required repository secrets:

- `CLOUDFLARE_API_KEY` — Cloudflare API token with Workers Scripts write access and permission to attach the custom domain.
- `CLOUDFLARE_ACCOUNT_ID` — Cloudflare account ID.

From this directory, deployment can also be run manually:

```bash
npm install
npm run dry-run
npm run deploy
```

The deployment uses Wrangler v4 and the static assets directory configured in `wrangler.jsonc`. Documentation and development files are excluded by `.assetsignore`.

## Accessibility and behavior

- Semantic sections and landmarks with accessible navigation labels.
- Mobile menu exposes its expanded state through `aria-expanded`.
- Diagram images include descriptive alternative text.
- Motion is reduced when the user enables `prefers-reduced-motion`.
- Diagram cards are responsive and their full-resolution images can be opened separately.

## Security model

This homepage is a static project overview. It does not expose the private inference endpoint, OpenObserve API, Prometheus API or host management interfaces. The underlying stack's AI worker generates recommendations and drafts; human review and explicit approval remain required before security changes are applied.
