// EP Payment Adapter — MPP + x402 agnostic
// x402 path: NEVER touched — byte-for-byte identical
// MPP path: new, behind MPP_ENABLED feature flag

const MPP_ENABLED = process.env.MPP_ENABLED !== 'false';

function detectProtocol(req) {
  const body = req.body || {};
  const headers = req.headers || {};

  if (MPP_ENABLED) {
    const hasMPPHeader = headers['x-mpp-challenge'] ||
                         headers['x-mpp-version'];
    const hasMPPBody = body.type &&
      typeof body.type === 'string' &&
      body.type.includes('paymentauth.org/problems/payment-required');
    if (hasMPPHeader || hasMPPBody) return 'mpp';
  }

  return 'x402';
}

function normalizePaymentRequest(protocol, req) {
  const body = req.body || {};

  if (protocol === 'mpp') {
    return {
      protocol: 'mpp',
      amount: body.amount || '0',
      currency: 'usd',
      network: 'tempo',
      challengeId: body.challengeId,
      payTo: body.recipient,
      metadata: {
        type: 'mpp',
        stripePaymentIntentId: body.paymentIntentId
      }
    };
  }

  return {
    protocol: 'x402',
    amount: body.amount || '0',
    currency: body.currency || 'usdc',
    network: 'base',
    payTo: body.payTo,
    metadata: { type: 'x402' }
  };
}

function buildPaymentResponse(protocol, epResult, normalizedPayment) {
  if (protocol === 'mpp' && MPP_ENABLED) {
    return {
      type: 'https://paymentauth.org/problems/payment-receipt',
      status: 200,
      receipt: {
        challengeId: normalizedPayment.challengeId,
        amount: normalizedPayment.amount,
        currency: normalizedPayment.currency,
        network: normalizedPayment.network,
        settledAt: new Date().toISOString(),
        epProof: epResult.proof_hash,
        epValid: epResult.valid,
        epRiskScore: epResult.risk_score
      },
      verification: {
        payment_verified: true,
        authorization_verified: epResult.valid,
        proof_hash: epResult.proof_hash,
        verified_at: new Date().toISOString()
      }
    };
  }

  return null;
}

export { detectProtocol, normalizePaymentRequest, buildPaymentResponse, MPP_ENABLED };
