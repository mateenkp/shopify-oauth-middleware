# KatiCRM Shopify OAuth Middleware - Deployment Checklist

## 📋 Pre-Deployment Checklist

### 1. Code Preparation
- [ ] All code pushed to GitHub repository
- [ ] `.gitignore` includes `.env` file
- [ ] No sensitive credentials in code
- [ ] `package.json` has correct dependencies
- [ ] README.md is up to date

### 2. Shopify Partner Dashboard Setup
- [ ] App created in Shopify Partners
- [ ] App name set (cannot contain "Shopify")
- [ ] API Key obtained
- [ ] API Secret obtained and stored securely
- [ ] App scopes configured
- [ ] App URL placeholder added (update after Railway deployment)
- [ ] Redirect URLs placeholder added (update after Railway deployment)

### 3. Bubble.io Backend Workflows
- [ ] `store_shopify_token` workflow created
- [ ] `gdpr_data_request` workflow created
- [ ] `gdpr_customer_redact` workflow created
- [ ] `gdpr_shop_redact` workflow created
- [ ] All workflows tested with Postman/curl
- [ ] Workflow URLs copied for environment variables
- [ ] Privacy rules configured for Shopify_Connection data type

## 🚀 Railway Deployment Steps

### Step 1: Initial Deployment

1. **Connect Repository**
   ```
   - Go to https://railway.app
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Authorize Railway to access your GitHub
   - Select your repository
   - Railway will auto-detect Node.js and deploy
   ```

2. **Wait for First Deployment**
   ```
   - Railway will run npm install and npm start
   - Check logs for any errors
   - Note your deployment URL (looks like: abc123.up.railway.app)
   ```

3. **Get Your Railway URL**
   ```
   - Click "Settings" tab
   - Scroll to "Domains"
   - Copy the generated Railway domain
   - Example: katicrm-oauth-production.up.railway.app
   ```

### Step 2: Add Redis (Recommended)

1. **Add Redis Database**
   ```
   - In your Railway project
   - Click "New" → "Database" → "Add Redis"
   - Redis will deploy automatically
   - REDIS_URL environment variable auto-injected
   ```

2. **Verify Redis Connection**
   ```
   - Check deployment logs for: "✅ Redis connected"
   - If you see this, Redis is working correctly
   ```

### Step 3: Configure Environment Variables

Go to Railway project → Variables tab, add these one by one:

#### Required Shopify Variables
```bash
SHOPIFY_API_KEY=<from-shopify-partner-dashboard>
SHOPIFY_API_SECRET=<from-shopify-partner-dashboard>
SHOPIFY_SCOPES=read_customers,write_customers,read_orders,write_orders,read_products,write_products,read_inventory,write_inventory,read_locations,read_discounts,write_discounts,read_company_locations,read_fulfillments,write_fulfillments
```

#### Required App Variables
```bash
APP_URL=https://your-railway-url.up.railway.app
NODE_ENV=production
ADMIN_PASSWORD=<your-secure-password>
```

#### Required Bubble.io Variables
```bash
BUBBLE_API_ENDPOINT=https://d334.bubble.is/version-test/api/1.1/wf/store_shopify_token
BUBBLE_SUCCESS_URL=https://d334.bubble.is/version-test/shopify_dashboard
BUBBLE_ERROR_URL=https://d334.bubble.is/version-test/error
BUBBLE_GDPR_DATA_REQUEST=https://d334.bubble.is/version-test/api/1.1/wf/gdpr_data_request
BUBBLE_GDPR_CUSTOMER_REDACT=https://d334.bubble.is/version-test/api/1.1/wf/gdpr_customer_redact
BUBBLE_GDPR_SHOP_REDACT=https://d334.bubble.is/version-test/api/1.1/wf/gdpr_shop_redact
```

#### Optional (Redis auto-set if you added Redis database)
```bash
# REDIS_URL=redis://... (auto-injected by Railway)
```

### Step 4: Update Shopify Partner Dashboard

Now that you have your Railway URL, update Shopify:

1. **App URL**
   ```
   - Go to Shopify Partners → Apps → [Your App] → App setup
   - App URL: https://your-railway-url.up.railway.app
   ```

2. **Allowed Redirection URLs**
   ```
   - In same App setup section
   - Add: https://your-railway-url.up.railway.app/auth/callback
   - Click "Save"
   ```

3. **GDPR Webhooks** (Auto-discovered during review)
   ```
   Note: You don't manually add these. Shopify auto-discovers them.
   But verify these URLs are accessible:
   - https://your-railway-url.up.railway.app/webhooks/customers/data_request
   - https://your-railway-url.up.railway.app/webhooks/customers/redact
   - https://your-railway-url.up.railway.app/webhooks/shop/redact
   ```

## ✅ Post-Deployment Verification

### 1. Health Check
```bash
curl https://your-railway-url.up.railway.app/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2025-10-28T...",
  "version": "3.0.0",
  "dependencies": {
    "storage": { "healthy": true },
    "bubble": { "healthy": true }
  }
}
```

**If health check fails:**
- Check Railway logs for errors
- Verify all environment variables are set
- Ensure Bubble endpoints are accessible

### 2. Test OAuth Flow

1. **Create Test Store**
   ```
   - Go to Shopify Partners → Stores
   - Create development store
   - Use this store for testing
   ```

2. **Test Installation**
   ```
   Method 1: Direct URL
   https://your-railway-url.up.railway.app/?shop=yourtest
   
   Method 2: From Shopify Partners
   - Go to Apps → [Your App] → Test on development store
   - Select your test store
   - Click "Test app"
   ```

3. **Verify OAuth Success**
   ```
   - Should redirect to Shopify authorization screen
   - After approving, should redirect to your Bubble success URL
   - Check Railway logs for: "✅ OAuth flow completed successfully"
   - Check Bubble database for new Shopify_Connection record
   ```

### 3. Test Admin Endpoints

```bash
# Get system status
curl -H "Authorization: Bearer YOUR_ADMIN_PASSWORD" \
  https://your-railway-url.up.railway.app/admin/status

# Check specific shop
curl -H "Authorization: Bearer YOUR_ADMIN_PASSWORD" \
  https://your-railway-url.up.railway.app/admin/shop/yourtest.myshopify.com
```

### 4. Test Webhook Verification

Shopify will automatically test webhooks during app review. You can manually test:

```bash
# Generate test HMAC (replace YOUR_SECRET with SHOPIFY_API_SECRET)
PAYLOAD='{"shop_domain":"test.myshopify.com","shop_id":1234}'
HMAC=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "YOUR_SECRET" -binary | base64)

curl -X POST https://your-railway-url.up.railway.app/webhooks \
  -H "X-Shopify-Hmac-Sha256: $HMAC" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"
```

Expected: `200 OK` with "Webhook received and verified"

## 🔍 Troubleshooting Deployment Issues

### Issue: Health check fails with storage error

**Solution:**
```bash
# If using Redis, check Railway logs for Redis connection
# Should see: "✅ Redis connected"

# If Redis isn't connecting:
1. Verify Redis service is running in Railway
2. Check REDIS_URL is set (should be automatic)
3. Restart the app service

# If no Redis (development):
# Should see warning: "⚠️ Using in-memory storage"
# This is OK for testing but NOT for production
```

### Issue: Bubble health check fails

**Solution:**
```bash
# Test Bubble endpoint manually:
curl https://d334.bubble.is/version-test/

# If it fails:
1. Check if Bubble app is deployed
2. Verify workflow endpoints are correct
3. Ensure workflows are public (not requiring auth)
```

### Issue: OAuth fails with "redirect_uri not whitelisted"

**Solution:**
```bash
# Verify these match EXACTLY:
1. Railway: APP_URL environment variable
2. Shopify: Allowed redirection URLs

# Common mistakes:
- Extra "/" at end of URL
- HTTP instead of HTTPS
- Typo in URL
- App URL and callback URL don't match
```

### Issue: "HMAC verification failed"

**Solution:**
```bash
# Check these match EXACTLY:
1. Railway: SHOPIFY_API_SECRET environment variable
2. Shopify Partner Dashboard: API secret

# Reset if needed:
1. Go to Shopify Partners → Apps → [Your App]
2. Rotate API credentials
3. Update SHOPIFY_API_KEY and SHOPIFY_API_SECRET in Railway
4. Redeploy app
```

## 📊 Monitoring Setup

### 1. Railway Built-in Monitoring
```
- View logs in Railway dashboard
- Check CPU/Memory usage graphs
- Set up deploy notifications
- Monitor health check status
```

### 2. External Monitoring (Optional)

**UptimeRobot** (Free)
```
- Monitor: https://your-railway-url.up.railway.app/health
- Check interval: 5 minutes
- Alert via email/SMS on downtime
```

**Sentry** (Error Tracking)
```bash
# Add to package.json:
npm install @sentry/node

# Add to server.js:
const Sentry = require("@sentry/node");
Sentry.init({ dsn: "YOUR_SENTRY_DSN" });

# Add to environment variables:
SENTRY_DSN=https://...@sentry.io/...
```

## 🎯 Pre-Production Checklist

Before submitting to Shopify App Store:

- [ ] All tests pass on development store
- [ ] OAuth flow works correctly
- [ ] Webhooks verified by Shopify
- [ ] Health checks return 200 OK
- [ ] Redis configured for production
- [ ] ADMIN_PASSWORD changed from default
- [ ] Monitoring set up
- [ ] Logs showing no errors
- [ ] SSL certificate valid (automatic with Railway)
- [ ] All Bubble workflows tested
- [ ] Error handling tested (disconnect Bubble and verify graceful degradation)

## 🚀 Go Live!

Once all checks pass:

1. **Submit App for Review**
   ```
   - Shopify Partners → Apps → [Your App]
   - Click "Submit for review"
   - Fill out app listing details
   - Wait for approval (typically 2-5 business days)
   ```

2. **Monitor First Installs**
   ```
   - Check Railway logs during first installs
   - Monitor Bubble database for new connections
   - Watch for any error patterns
   ```

3. **Scale as Needed**
   ```
   - Railway auto-scales to some extent
   - For high traffic, upgrade Railway plan
   - Consider adding more Redis memory
   - Set up read replicas if needed
   ```

## 📞 Support

If you encounter issues:

1. Check Railway logs first
2. Review this checklist
3. Test health endpoint
4. Verify all environment variables
5. Check Shopify Partner Dashboard for app status

---

**Deployment Completed: ________ (date)**  
**Deployed By: ________ (name)**  
**Railway URL: ________ (url)**  
**App Submission Date: ________ (date)**
