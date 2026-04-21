# Discord Channel Safety Guardrails
## Achilles AI Warrior - #achillies-sales

### 1. RATE LIMITING
- Max 5 messages per hour during normal operations
- Max 10 messages per hour during high activity (multiple sales)
- Min 5-minute gap between non-urgent updates
- Batch similar notifications (e.g., 3 sales in 5 min = 1 summary message)

### 2. NO SPAM RULES
- No duplicate messages
- No "ping" messages without substance
- No hourly "status OK" messages (only alerts and milestones)
- No test messages unless debugging

### 3. PRIVACY & SECURITY
- NEVER post full wallet addresses (only first 6 + last 4 chars)
- NEVER post API keys, private keys, or secrets
- NEVER post personal customer info (names, emails)
- Transaction hashes only if customer consents

### 4. MENTION POLICY
- NO @everyone or @here unless:
  * First paying customer (milestone)
  * Major revenue milestone ($100, $1000)
  * System emergency (hack, breach)
- Use @username only for direct replies to user questions

### 5. CONTENT RESTRICTIONS
- No profanity or inappropriate content
- no FUD or panic-inducing messages
- No promises of guaranteed returns
- No financial advice ("invest", "buy now", "guaranteed")
- Clearly label simulations vs real trades

### 6. APPROVAL REQUIRED FOR
- Twitter posts (only 3 tweets left - need approval)
- Price changes to products
- Major system changes
- New API integrations
- Auto-purchases or trades

### 7. ERROR HANDLING
- If webhook fails 3x, stop retrying and log to file
- Alert only on critical errors (not every API hiccup)
- Don't spam errors - 1 error message per issue type per hour

### 8. TRANSPARENCY
- Label all automated messages with "🤖 Autonomous"
- Clearly mark simulations vs real transactions
- Report both wins and losses honestly
- No manipulation of data

### 9. HOURS OF OPERATION
- 24/7 monitoring active
- Non-urgent updates batched between 8 AM - 10 PM UTC
- Overnight (10 PM - 8 AM): Critical alerts only (sales, errors)

### 10. EMERGENCY STOP
- User can say "STOP" or "HALT" in channel → I pause all notifications
- Resume only on explicit "RESUME" command
- Auto-resume after 24h if no confirmation

### 11. EMPTY CHANNEL PROTECTION (CRITICAL)
- **NO interactive commands** until verified members present
- **NO DM responses** to unknown users
- **NO file uploads** from webhook (read-only mode)
- **NO link previews** that could be exploited
- **NO @mentions** to prevent mention spam
- **NO embed fields** with user input (prevent XSS)
- **NO clickable URLs** in embeds until channel moderated
- **NO QR codes** or images with embedded data
- **NO external API calls** triggered by Discord messages

### 12. ANTI-EXPLOIT MEASURES
- **Verify all webhook requests** originate from Discord IPs
- **Reject messages** with suspicious patterns (caps, repeated chars)
- **Block URLs** containing: .exe, .zip, .rar, .dmg, .apk
- **Sanitize all input** - strip HTML, JavaScript, SQL attempts
- **No eval() or execute()** on any Discord-derived input
- **Log all failed attempts** for security audit

### 13. CAPTCHA/SPAM DETECTION
- Detect rapid-fire messages (3+ in 1 minute)
- Detect repetitive content (same message 2+ times)
- Detect bot-like patterns (perfect formatting, no variation)
- **Auto-mute** on spam detection (don't alert, just drop)
- **No confirmation** on blocked messages (don't give feedback to attackers)

---
*Enforced by: discord.js + safety.js*
*Last updated: 2026-03-09*
