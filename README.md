# Achilles AI Agent — Render Deployment

Autonomous AI agent landing page and dashboard.

## Service
- **URL**: https://achilles-cn9c.onrender.com
- **Status**: Production

## Build & Deploy

```bash
# Local development
npm install
npm run dev

# Deploy to Render
git push origin master
```

## Features
- Autonomous agent status dashboard
- Real-time P&L display
- Product listings
- Treasury wallet monitoring
- Committee cycle logs

## Environment Variables
- `NODE_ENV`: production
- `PORT`: 10000 (Render default)

## Execution Protocol (EP) — AgentIAM

Pre-execution policy validation for autonomous AI agents. Five pillars:
1. **Identity** — ERC-8004 on-chain agent registration on Base
2. **Access** — Policy sets enforced before execution
3. **Management** — Cryptographic proof hashes for every action
4. **Reputation** — Talent Protocol operator verification
5. **Payments** — MPP + x402 agnostic adapter

---

## Payment Protocol Support

EP supports both major agentic payment protocols as an authorization layer that runs before any payment fires.

### x402 (Coinbase / Base)
- Open standard for HTTP 402 stablecoin payments
- EP validates agent authorization pre-execution
- x402 response includes EP proof_hash
- Network: Base mainnet, USDC
- Docs: https://x402.org

### MPP — Machine Payments Protocol (Stripe / Tempo)
- Co-authored by Stripe and Tempo, launched March 18 2026
- EP proof_hash is embedded INSIDE the MPP receipt
- One receipt = payment verified (Stripe) + authorized (EP)
- No other agent infrastructure layer offers dual verification
- Network: Tempo mainnet, stablecoins + cards via SPT
- Docs: https://docs.stripe.com/payments/machine/mpp

### Protocol Detection
EP auto-detects MPP vs x402 from request headers. Both protocols normalize to the same internal PaymentRequest. x402 path: byte-for-byte identical, zero breaking changes. MPP path: behind `MPP_ENABLED=true` feature flag.

### Endpoints
```
GET  /ep/payment/status   — { x402: true, mpp: true }
POST /ep/payment/verify   — verify receipt + proof_hash
POST /ep/validate         — accepts optional payment_context
```

### The Moat
```json
{
  "payment_receipt": {
    "receipt": {
      "epProof": "0x6094ef...",
      "payment_verified": true,
      "authorization_verified": true
    }
  }
}
```
EP proof hash embedded in MPP receipt = dual verification in one receipt. Stripe verifies payment. EP verifies authorization. Same receipt. No other layer does this.

## Repository
https://github.com/achilliesbot/achillies-render
