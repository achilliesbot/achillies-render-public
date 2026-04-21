# EP AgentIAM Pre-Execution Guard

## Description
Fast pre-execution policy check for autonomous agents.
Boolean pass/fail + cryptographic proof_hash. x402 on Base.
No trust required. Framework agnostic.

## Install
To use EP from OpenClaw:
> install ep-guard from https://achillesalpha.onrender.com/ep/SKILL.md

## Usage
POST https://achillesalpha.onrender.com/ep/validate
Required: agent_id (string), action (string)
Optional: policy_set_id (string), payload (object)

## Pricing
$0.01/call (basic-guard) — via Virtuals ACP or direct x402
Also available: $0.05, $0.10, $2.00 tiers — see /ep/llms-full.txt

## Response
{
  "valid": true|false,
  "proof_hash": "sha256_hash",
  "policy_set_id": "string",
  "timestamp": "ISO8601"
}

## ACP
Discoverable on Virtuals ACP as ep_guard (agent ID: 28821)
https://app.virtuals.io/acp

## Endpoints
- POST /ep/validate
- POST /ep/swarm/validate
- GET  /ep/status
- GET  /ep/army
- GET  /ep/manifest.json
- GET  /agent.json
- GET  /agent_log.json
