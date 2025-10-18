# Shopify OAuth Middleware for KatiCRM

This middleware service handles OAuth authentication between Shopify and Bubble.io for KatiCRM.

## What it does:
- Verifies HMAC signatures from Shopify
- Handles OAuth authorization flow
- Exchanges authorization codes for access tokens
- Stores tokens securely in Bubble.io

## Deployed on Railway.app

### Environment Variables Required:
- `SHOPIFY_API_KEY` - Your Shopify app's API key
- `SHOPIFY_API_SECRET` - Your Shopify app's API secret
- `BUBBLE_API_ENDPOINT` - Your Bubble workflow URL
- `APP_URL` - This Railway app's URL
- `BUBBLE_SUCCESS_URL` - Where to redirect after success
- `BUBBLE_ERROR_URL` - Where to redirect on error

### Endpoints:
- `GET /health` - Health check
- `GET /install?shop=store.myshopify.com` - Start OAuth
- `GET /callback` - OAuth callback (used by Shopify)# shopify-oauth-middleware
OAuth middleware for KatiCRM Shopify integration
