#!/usr/bin/env bash

# ============================================================================
#  Achilles EP — Quick Test Script
# ============================================================================
#
#  This script calls the NoLeak endpoint without a wallet to show you
#  the 402 Payment Required response. This proves the endpoint is live
#  and protected by x402 micropayments.
#
#  Usage:
#    chmod +x try-ep.sh
#    ./try-ep.sh
#
# ============================================================================

set -e

EP_URL="https://achillesalpha.onrender.com/x402/noleak"

echo "============================================================"
echo "  Achilles EP — NoLeak Endpoint Test"
echo "============================================================"
echo ""
echo "  Endpoint: $EP_URL"
echo "  Cost:     \$0.01 USDC per call (Base Mainnet)"
echo ""
echo "  Sending request without payment credentials..."
echo ""

HTTP_CODE=$(curl -s -o /tmp/ep-response.json -w "%{http_code}" \
  -X POST "$EP_URL" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"demo-agent","execution_hash":"0xabc123"}')

echo "  HTTP Status: $HTTP_CODE"
echo ""
echo "  Response:"
cat /tmp/ep-response.json 2>/dev/null | python3 -m json.tool 2>/dev/null || cat /tmp/ep-response.json 2>/dev/null
echo ""
echo ""

if [ "$HTTP_CODE" = "402" ]; then
  echo "  ✓ Endpoint is live and payment-gated (402 Payment Required)."
  echo ""
  echo "  NEXT STEPS"
  echo "  ----------"
  echo "  To make a paid call, use the x402 protocol:"
  echo ""
  echo "    1. npm install @x402/fetch viem"
  echo "    2. Download the full demo script:"
  echo "       curl -O https://achillesalpha.onrender.com/demo.js"
  echo "    3. Set your Base wallet private key:"
  echo "       export BASE_PRIVATE_KEY=\"0xYOUR_KEY\""
  echo "    4. Run: node demo.js"
  echo ""
  echo "  Your wallet needs USDC on Base Mainnet."
  echo ""
  echo "  AVAILABLE SERVICES"
  echo "  ------------------"
  echo "  POST /x402/noleak      \$0.01  Execution integrity check"
  echo "  POST /x402/memguard    \$0.01  Memory state verification"
  echo "  POST /x402/riskoracle  \$0.01  Pre-action risk scoring"
  echo "  POST /x402/secureexec  \$0.01  Tool execution security"
  echo "  POST /x402/flowcore    \$0.02  Full orchestration pipeline"
  echo ""
  echo "  Docs: https://achillesalpha.onrender.com/ep"
elif [ "$HTTP_CODE" = "200" ]; then
  echo "  ✓ Endpoint returned 200 OK."
  echo "    The endpoint may not have payment gating enabled yet."
else
  echo "  ⚠ Unexpected response code: $HTTP_CODE"
  echo "    Check that the service is running."
fi

echo ""
echo "============================================================"

rm -f /tmp/ep-response.json
