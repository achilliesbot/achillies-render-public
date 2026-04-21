#!/usr/bin/env node

// ============================================================================
//  Achilles EP (Execution Protocol) — x402 Demo Script
// ============================================================================
//
//  This script demonstrates how to make a paid API call to an Achilles EP
//  service using the x402 micropayment protocol on Base Mainnet.
//
//  SETUP
//  -----
//  1. Install dependencies:
//
//       npm install @x402/fetch viem
//
//  2. Set your Base wallet private key as an environment variable:
//
//       export BASE_PRIVATE_KEY="0xYOUR_PRIVATE_KEY_HERE"
//
//     Your wallet must hold USDC on Base Mainnet to pay for the call.
//     NoLeak costs $0.01 per call.
//
//  3. Run the script:
//
//       node demo.js
//
//  WHAT THIS DOES
//  --------------
//  - Calls the NoLeak endpoint (execution integrity check)
//  - x402 handles the USDC micropayment automatically
//  - You receive a signed integrity verification for your agent's execution
//
//  ENDPOINTS AVAILABLE
//  -------------------
//  POST /x402/noleak      — $0.01 — Execution integrity check
//  POST /x402/memguard    — $0.01 — Memory state verification
//  POST /x402/riskoracle  — $0.01 — Pre-action risk scoring
//  POST /x402/secureexec  — $0.01 — Tool execution security
//  POST /x402/flowcore    — $0.02 — Full orchestration pipeline
//
//  DOCS: https://achillesalpha.onrender.com/ep
// ============================================================================

import wrapFetch from "@x402/fetch";
import { createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";

// ---------------------------------------------------------------------------
//  Configuration
// ---------------------------------------------------------------------------

const EP_BASE_URL = "https://achillesalpha.onrender.com";
const NOLEAK_ENDPOINT = `${EP_BASE_URL}/x402/noleak`;

const privateKey = process.env.BASE_PRIVATE_KEY;

if (!privateKey) {
  console.error("\n  ERROR: BASE_PRIVATE_KEY environment variable is not set.\n");
  console.error("  Export your Base wallet private key first:");
  console.error('    export BASE_PRIVATE_KEY="0xYOUR_PRIVATE_KEY_HERE"\n');
  process.exit(1);
}

// ---------------------------------------------------------------------------
//  Create wallet client and wrap fetch with x402 payment handling
// ---------------------------------------------------------------------------

const account = privateKeyToAccount(privateKey);

const walletClient = createWalletClient({
  account,
  chain: base,
  transport: http(),
});

const payingFetch = wrapFetch(fetch, walletClient);

// ---------------------------------------------------------------------------
//  Make the paid API call
// ---------------------------------------------------------------------------

async function main() {
  console.log("=".repeat(60));
  console.log("  Achilles EP — NoLeak x402 Demo");
  console.log("=".repeat(60));
  console.log();
  console.log(`  Wallet:   ${account.address}`);
  console.log(`  Endpoint: ${NOLEAK_ENDPOINT}`);
  console.log(`  Cost:     $0.01 USDC (Base Mainnet)`);
  console.log();
  console.log("  Sending request...");
  console.log();

  try {
    const response = await payingFetch(NOLEAK_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agent_id: "demo-agent",
        execution_hash: "0xabc123",
      }),
    });

    const data = await response.json();

    console.log("  Response status:", response.status);
    console.log();
    console.log("  Result:");
    console.log(JSON.stringify(data, null, 2));
    console.log();
    console.log("  Payment was handled automatically via x402.");
    console.log("  Your agent now has a signed integrity check.");
    console.log();
    console.log("=".repeat(60));
  } catch (err) {
    console.error("  Request failed:", err.message);
    console.error();

    if (err.message.includes("402")) {
      console.error("  This likely means the x402 payment could not be completed.");
      console.error("  Check that your wallet has USDC on Base Mainnet.");
    }

    process.exit(1);
  }
}

main();
