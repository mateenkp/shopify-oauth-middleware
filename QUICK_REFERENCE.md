# Quick Reference Guide

## 🚀 Common Operations

### Check System Health
```bash
curl https://your-app.up.railway.app/health
```

### Check Specific Shop Connection
```bash
curl -H "Authorization: Bearer YOUR_ADMIN_PASSWORD" \
  https://your-app.up.railway.app/admin/shop/mystore.myshopify.com
```

### View Full System Status
```bash
curl -H "Authorization: Bearer YOUR_ADMIN_PASSWORD" \
  https://your-app.up.railway.app/admin/status
```

### Test OAuth Flow
```
https://your-app.up.railway.app/?shop=teststore
```

### View Railway Logs
```
1. Go to Railway dashboard
2. Click your project
3. Click "Deployments"
4. Click on latest deployment
5. View logs in real-time
```

## 🔍 Reading Structured Logs

### Log Format
```json
{
  "level": "info",
  "timestamp": "2025-10-28T19:52:54.869Z",
  "message": "OAuth flow completed successfully",
  "shop": "calltronix.myshopify.com",
  "requestId": "abc123xyz"
}
```

### Filter Logs by Level
```bash
# In Railway dashboard logs, search for:
"level":"error"    # Only errors
"level":"warn"     # Only warnings
"level":"info"     # Info messages
```

### Find Specific Request
```bash
# In logs, search for request ID from error:
"requestId":"abc123xyz"
```

### Track Specific Shop
```bash
# Search for shop domain:
"shop":"mystore.myshopify.com"
```

## 🐛 Troubleshooting Quick Fixes

### Issue: OAuth fails immediately

**Check:**
```bash
# 1. Verify environment variables
curl -H "Authorization: Bearer YOUR_ADMIN_PASSWORD" \
  https://your-app.up.railway.app/admin/status

# Look for:
{
  "configuration": {
    "oauthEnabled": true  // Should be true
  }
}

# 2. Test from Shopify directly (not your app)
https://your-app.up.railway.app/?shop=teststore
```

**Fix:**
- Ensure `SHOPIFY_API_KEY` and `SHOPIFY_API_SECRET` are set
- Verify no extra spaces in environment variables
- Check Shopify Partner Dashboard has correct redirect URLs

### Issue: "redirect_uri is not whitelisted"

**Check:**
```bash
# Compare these three URLs - they must match EXACTLY:
1. Railway: echo $APP_URL
2. Shopify Partner Dashboard → App setup → App URL
3. Shopify Partner Dashboard → Allowed redirection URLs

# Common mistakes:
❌ https://my-app.up.railway.app/    # Extra trailing slash
❌ http://my-app.up.railway.app      # HTTP instead of HTTPS
❌ https://my-app.up.railway.app/auth # Wrong path
✅ https://my-app.up.railway.app      # Correct
```

**Fix:**
1. Get exact Railway URL (no trailing slash)
2. Update `APP_URL` in Railway variables
3. Update both URLs in Shopify Partner Dashboard
4. Redeploy Railway app

### Issue: Webhooks failing verification

**Check:**
```bash
# Test webhook endpoint
curl -X POST https://your-app.up.railway.app/webhooks \
  -H "Content-Type: application/json" \
  -d '{"test":"data"}'

# Should return: 401 Unauthorized (this is correct - needs HMAC)
```

**Debug:**
```bash
# In Railway logs, search for:
"Webhook HMAC verification failed"

# If you see this, check:
1. SHOPIFY_API_SECRET matches Shopify Partner Dashboard
2. No spaces in SHOPIFY_API_SECRET variable
3. Secret wasn't rotated in Shopify
```

**Fix:**
1. Go to Shopify Partner Dashboard → Apps → [Your App]
2. Copy API secret key
3. Update `SHOPIFY_API_SECRET` in Railway
4. Redeploy app

### Issue: Health check returns 503

**Check:**
```bash
curl https://your-app.up.railway.app/health
```

**Response tells you what's wrong:**
```json
{
  "status": "degraded",
  "dependencies": {
    "storage": {
      "healthy": false,
      "message": "Connection refused"  // Redis is down!
    },
    "bubble": {
      "healthy": false,
      "message": "Request timeout"     // Bubble is slow/down!
    }
  }
}
```

**Fix:**
- If storage unhealthy: Check Redis in Railway dashboard
- If bubble unhealthy: Check if Bubble app is deployed
- Both unhealthy: Check Railway app itself isn't out of memory

### Issue: Shop installed but not in Bubble database

**Check Railway logs:**
```bash
# Search for shop domain, look for:
"📤 Sending shop data to Bubble"
"✅ Data sent to Bubble successfully"
OR
"❌ Error sending to Bubble"
```

**If error sending to Bubble:**
```bash
# Check the error details in logs
# Common issues:
1. BUBBLE_API_ENDPOINT URL wrong
2. Bubble workflow requires authentication
3. Bubble app not deployed
4. Network timeout
```

**Fix:**
1. Test Bubble endpoint manually:
```bash
curl -X POST https://d334.bubble.is/version-test/api/1.1/wf/store_shopify_token \
  -H "Content-Type: application/json" \
  -d '{
    "shop": "test.myshopify.com",
    "access_token": "test123",
    "installed_at": "2025-10-28T00:00:00Z"
  }'
```

2. Verify workflow is public (no auth required)
3. Check Bubble app status
4. Verify `BUBBLE_API_ENDPOINT` URL is correct

### Issue: Redis connection failed

**Check logs for:**
```bash
"❌ Redis error"
```

**Check Railway:**
1. Go to Railway dashboard
2. Verify Redis service is running
3. Check Redis memory usage (shouldn't be full)
4. Verify `REDIS_URL` environment variable exists

**Fix:**
```bash
# Option 1: Restart Redis service in Railway
# Option 2: Remove REDIS_URL (app will use in-memory storage)
# Option 3: Recreate Redis database in Railway
```

### Issue: Rate limit exceeded

**Logs show:**
```json
{
  "level": "warn",
  "message": "Rate limit exceeded",
  "ip": "192.168.1.1"
}
```

**This is actually GOOD** - means rate limiting is protecting you!

**If legitimate traffic:**
```javascript
// In server.js, adjust limits:

// OAuth limiter
const oauthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,  // Increase this if needed: 50, 100, etc.
});
```

Redeploy after changing.

## 🔐 Security Checklist

### Daily
- [ ] Check Railway logs for suspicious activity
- [ ] Verify health endpoint returns 200 OK

### Weekly
- [ ] Review admin endpoint access logs
- [ ] Check for failed authentication attempts
- [ ] Verify no strange shop installations

### Monthly
- [ ] Rotate ADMIN_PASSWORD
- [ ] Review and update dependencies (npm outdated)
- [ ] Check for security advisories (npm audit)
- [ ] Review Railway usage and costs

### Quarterly
- [ ] Test disaster recovery (backup/restore)
- [ ] Review and update documentation
- [ ] Performance testing with load
- [ ] Security audit

## 📊 Performance Monitoring

### Key Metrics to Watch

**Railway Dashboard:**
- CPU usage (should be <50% average)
- Memory usage (should be <80% max)
- Response time (should be <500ms P95)
- Error rate (should be <1%)

**Health Endpoint:**
```bash
# Check every 5 minutes
curl https://your-app.up.railway.app/health

# Alert if status != "healthy"
```

### When to Scale Up

Scale if you see:
- ⚠️ CPU consistently >70%
- ⚠️ Memory consistently >80%
- ⚠️ Response times >1 second
- ⚠️ Error rate >5%

**How to Scale (Railway):**
1. Upgrade Railway plan (more CPU/RAM)
2. Add Redis if not using it
3. Consider multiple instances (Pro plan)

## 🔄 Maintenance Windows

### Zero-Downtime Deployment
Railway supports zero-downtime deployments automatically:
```bash
git push  # Railway deploys new version, keeps old running until new is ready
```

### Planned Maintenance
If you need to take app offline:

1. **Before maintenance:**
```bash
# In Shopify Partner Dashboard:
# Temporarily set app to "Draft" mode
# Merchants can't install during this time
```

2. **During maintenance:**
```bash
# Do your updates
# Test thoroughly
```

3. **After maintenance:**
```bash
# Test health endpoint
curl https://your-app.up.railway.app/health

# If healthy, set app back to "Public"
```

## 📞 Emergency Contacts

### Railway is Down
- Status: https://status.railway.app
- Twitter: @Railway
- Support: https://help.railway.app

### Shopify API Issues
- Status: https://www.shopifystatus.com
- Partners: https://partners.shopify.com
- Help: https://help.shopify.com/partners

### Bubble is Down
- Status: https://status.bubble.io
- Forum: https://forum.bubble.io
- Support: https://bubble.io/support

## 🎯 Quick Wins

### Improve Performance
1. Add Redis (5 min, $5/month)
2. Enable Railway Pro plan for better resources
3. Add CDN for static assets (if any)

### Improve Security
1. Rotate ADMIN_PASSWORD monthly
2. Enable 2FA on Railway account
3. Enable 2FA on Shopify Partners account
4. Add UptimeRobot monitoring

### Improve Reliability
1. Set up UptimeRobot health check monitoring
2. Configure Railway deploy notifications
3. Add Sentry for error tracking
4. Document runbooks for common issues

## 📝 Common Commands Reference

```bash
# View Railway logs (live)
railway logs --follow

# View last 100 log lines
railway logs --tail 100

# View environment variables
railway variables

# Set environment variable
railway variables set VARIABLE_NAME=value

# Deploy from CLI
railway up

# Check deployment status
railway status

# Open Railway dashboard
railway open

# Open app in browser
railway open --app
```

## ✅ Health Check Interpretation

### Healthy System
```json
{
  "status": "healthy",
  "version": "3.0.0",
  "dependencies": {
    "storage": { "healthy": true },
    "bubble": { "healthy": true }
  }
}
```
**Action:** None, system is good ✅

### Degraded - Storage Issue
```json
{
  "status": "degraded",
  "dependencies": {
    "storage": { "healthy": false, "message": "Connection refused" },
    "bubble": { "healthy": true }
  }
}
```
**Action:** Check Redis service in Railway

### Degraded - Bubble Issue
```json
{
  "status": "degraded",
  "dependencies": {
    "storage": { "healthy": true },
    "bubble": { "healthy": false, "message": "Request timeout" }
  }
}
```
**Action:** Check Bubble app status, verify workflows are deployed

### Degraded - Both
```json
{
  "status": "degraded",
  "dependencies": {
    "storage": { "healthy": false },
    "bubble": { "healthy": false }
  }
}
```
**Action:** Check Railway app isn't out of memory/CPU, check network connectivity

---

## 🆘 Emergency Rollback

If something is critically broken:

```bash
# Railway Dashboard Method (FASTEST):
1. Go to Railway Dashboard
2. Click "Deployments"
3. Find last working deployment
4. Click "Rollback"
5. Confirm

# Git Method:
git revert HEAD
git push

# Nuclear Option (if git is broken):
git reset --hard <last-good-commit>
git push --force
```

---

**Last Updated:** October 28, 2025  
**Maintainer:** ________  
**Emergency Contact:** ________
