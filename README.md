# Cookie Security Analyzer

A Manifest V3 Chrome extension built with TypeScript for inspecting cookies on the active tab and evaluating their security posture locally in the browser.

## Features

- Lists cookies for the active site in a dark security-dashboard style popup
- Shows cookie name, truncated value, domain, path, expiration, Secure, HttpOnly, SameSite, and third-party classification
- Assigns `SAFE`, `LOW RISK`, `MEDIUM RISK`, or `HIGH RISK` labels using local heuristics
- Supports search, risky-only filtering, expandable detail rows, and JSON export

## Build

```bash
npm run build
```

## Load In Chrome

1. Open `chrome://extensions`
2. Enable Developer mode
3. Click `Load unpacked`
4. Select this project folder
