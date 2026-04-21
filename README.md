# achillies-render (public mirror)

Source code for **achillesalpha.onrender.com** — the Achilles / Project Olympus main service.

This is a **scrubbed public mirror** of the private `achilliesbot/achillies-render` repo, provided for design, audit, and integration work. All API keys, tokens, and private credentials have been redacted and replaced with placeholders like `*_REDACTED_SET_VIA_ENV`. The canonical repo with full history is private.

## Layout

- `server.mjs` — single-file Express app, 2800+ lines, add-only
- `public/` — static HTML pages (index, loot, ep service pages)
- `src/adapters/` — x402 / payment protocol adapters
- `docs/` — integration notes

## Routes

Landing & products: `/`, `/loot`, `/quest`, `/tribute`, `/ep`, `/olympus`, `/delphi`, `/strategos`, `/agentiam`, `/pnl`, `/docs`, `/quickstart`, `/endpoints`, `/privacy`, `/terms`
EP services: `/noleak`, `/memguard`, `/riskoracle`, `/secureexec`, `/flowcore`
Manifests: `/.well-known/x402.json`, `/.well-known/x402-facilitator.json`, `/.well-known/agent.json`, `/.well-known/mcp.json`
x402 paid endpoints: `/x402/noleak`, `/x402/memguard`, `/x402/riskoracle`, `/x402/secureexec`, `/x402/flowcore`, `/x402/delphi*`, `/x402/audit`
Facilitator proxy: `/facilitator/*` → achillesalpha-facilitator.onrender.com

## License

Source available for reference. Not licensed for redistribution.
