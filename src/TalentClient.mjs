// Talent Protocol operator reputation verification
// Docs: https://github.com/talentprotocol/builder-data/blob/main/SKILL.md
// Fail open always — never block execution on API failure
// 3 second hard timeout — never slow EP response

export async function verifyOperator(walletAddress) {
  const apiKey = process.env.TALENT_API_KEY;

  if (!apiKey) {
    console.warn('[TalentClient] TALENT_API_KEY not set — failing open');
    return { verified: true, wallet: walletAddress, reason: 'api_key_missing_fail_open' };
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const response = await fetch(
      `https://api.talentprotocol.com/human_checkmark?wallet=${walletAddress}`,
      {
        headers: {
          'X-API-KEY': apiKey,
          'Content-Type': 'application/json'
        },
        signal: controller.signal
      }
    );
    clearTimeout(timeout);

    if (!response.ok) {
      console.warn(`[TalentClient] API error ${response.status} — failing open`);
      return { verified: true, wallet: walletAddress, reason: 'api_error_fail_open' };
    }

    const data = await response.json();
    return {
      verified: data.human_checkmark === true,
      wallet: walletAddress,
      reason: data.human_checkmark ? 'verified' : 'not_verified'
    };
  } catch (err) {
    console.warn(`[TalentClient] Request failed — failing open: ${err.message}`);
    return { verified: true, wallet: walletAddress, reason: 'timeout_fail_open' };
  }
}
