# OpenTweet API Integration

## API Key Stored
Key is in `.env` file (not committed to GitHub for security)

## Configuration
```bash
OPENTWEET_API_KEY=ot_PLACEHOLDER_REDACTED_FOR_PUBLIC_MIRROR
TWITTER_HANDLE=achillesalphaai
TWEETS_REMAINING=4
```

## Usage
See `opentweet.js` for the client library.

## Rate Limits
- 4 tweets remaining this month
- Use strategically

## Tweet Strategy
1. **Site launch announcement** (NOW)
2. **First customer celebration** (when it happens)
3. **Daily/weekly stats** (milestone-based)
4. **Product highlight** (feature-specific)

## API Endpoint Note
The OpenTweet API endpoint needs to be configured. 
Common patterns:
- `https://opentweet.io/api/v1/tweet`
- `https://api.opentweet.io/v1/tweet`
- `https://opentweet.io/v1/tweets`

Check your OpenTweet dashboard for the correct endpoint.
