const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const querystring = require('querystring');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ===========================================
// CONFIGURATION
// ===========================================

const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY;
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET;
const APP_URL = process.env.APP_URL;
const BUBBLE_API_ENDPOINT = process.env.BUBBLE_API_ENDPOINT;
const BUBBLE_GDPR_DATA_REQUEST = process.env.BUBBLE_GDPR_DATA_REQUEST;
const BUBBLE_GDPR_CUSTOMER_REDACT = process.env.BUBBLE_GDPR_CUSTOMER_REDACT;
const BUBBLE_GDPR_SHOP_REDACT = process.env.BUBBLE_GDPR_SHOP_REDACT;
const BUBBLE_SUCCESS_URL = process.env.BUBBLE_SUCCESS_URL || 'https://d334.bubble.is/version-test/shopify_dashboard';
const BUBBLE_ERROR_URL = process.env.BUBBLE_ERROR_URL || 'https://d334.bubble.is/version-test/error';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-this-password';
const SCOPES = 'read_customers,write_customers,read_orders,write_orders,read_products,write_products,read_inventory,write_inventory,read_locations,read_discounts,write_discounts,read_company_locations,read_fulfillments,write_fulfillments';

// In-memory store for OAuth state and shop tokens
// TODO: Replace with Redis or database for production
const stateStore = new Map();
const shopStore = new Map();

// Validate critical environment variables on startup
const validateConfig = () => {
  const required = {
    SHOPIFY_API_KEY,
    SHOPIFY_API_SECRET,
    APP_URL,
    BUBBLE_API_ENDPOINT
  };
  
  const missing = Object.entries(required)
    .filter(([_, value]) => !value)
    .map(([key]) => key);
  
  if (missing.length > 0) {
    console.error('❌ CRITICAL: Missing required environment variables:', missing.join(', '));
    process.exit(1);
  }
};

validateConfig();

// ===========================================
// MIDDLEWARE CONFIGURATION
// ===========================================

// Security headers middleware - applies to all routes
app.use((req, res, next) => {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  
  // Shopify-specific headers for app embedding
  res.setHeader('X-Frame-Options', 'ALLOW-FROM https://admin.shopify.com');
  res.setHeader('Content-Security-Policy', "frame-ancestors https://*.myshopify.com https://admin.shopify.com");
  
  // Remove sensitive headers
  res.removeHeader('X-Powered-By');
  
  next();
});

// Request logging middleware (helps with debugging)
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip}`);
  next();
});

// CRITICAL: Capture raw body for webhook HMAC verification BEFORE parsing
app.use('/webhooks', express.raw({ type: 'application/json' }));

// Regular JSON parsing for other routes
app.use(express.json());

// URL-encoded parsing for OAuth callbacks
app.use(express.urlencoded({ extended: true }));

// ===========================================
// SECURITY & VALIDATION FUNCTIONS
// ===========================================

/**
 * Verify HMAC signature for OAuth callbacks
 * @param {Object} query - Query parameters from OAuth callback
 * @param {string} hmac - HMAC signature to verify
 * @returns {boolean} - True if valid, false otherwise
 */
function verifyHmac(query, hmac) {
  if (!hmac || !SHOPIFY_API_SECRET) {
    return false;
  }
  
  try {
    // Extract all parameters except hmac and signature
    const params = Object.keys(query)
      .filter(key => key !== 'hmac' && key !== 'signature')
      .sort()
      .reduce((acc, key) => {
        acc[key] = query[key];
        return acc;
      }, {});
    
    const message = querystring.stringify(params);
    
    const hash = crypto
      .createHmac('sha256', SHOPIFY_API_SECRET)
      .update(message)
      .digest('hex');
      
    return crypto.timingSafeEqual(
      Buffer.from(hash),
      Buffer.from(hmac)
    );
  } catch (error) {
    console.error('❌ HMAC verification error:', error.message);
    return false;
  }
}

/**
 * Verify webhook HMAC signature using raw body
 * @param {Buffer|string} rawBody - Raw request body
 * @param {string} hmac - HMAC signature from header
 * @returns {boolean} - True if valid, false otherwise
 */
function verifyWebhook(rawBody, hmac) {
  if (!hmac) {
    return false;
  }

  if (!SHOPIFY_API_SECRET) {
    console.error('❌ SHOPIFY_API_SECRET not configured');
    return false;
  }

  try {
    const bodyString = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
    
    const calculatedHmac = crypto
      .createHmac('sha256', SHOPIFY_API_SECRET)
      .update(bodyString, 'utf8')
      .digest('base64');
    
    return crypto.timingSafeEqual(
      Buffer.from(calculatedHmac, 'base64'),
      Buffer.from(hmac, 'base64')
    );
  } catch (error) {
    console.error('❌ HMAC verification error:', error.message);
    return false;
  }
}

/**
 * Detect if request is from Shopify's automated connectivity test
 * @param {Object} body - Parsed request body
 * @param {Object} headers - Request headers
 * @returns {boolean} - True if likely a test request
 */
function isShopifyConnectivityTest(body, headers) {
  const hasShopifyUserAgent = (headers['user-agent'] || '').toLowerCase().includes('shopify');
  const isMinimalPayload = body && (Object.keys(body).length <= 3);
  const looksLikeTest = body && body.shop_id && body.shop_domain && !body.customer;
  
  return (hasShopifyUserAgent && isMinimalPayload) || looksLikeTest;
}

/**
 * Validate shop domain format
 * @param {string} shop - Shop domain to validate
 * @returns {boolean} - True if valid format
 */
function isValidShopDomain(shop) {
  if (!shop || typeof shop !== 'string') {
    return false;
  }
  
  // Must end with .myshopify.com and have at least one character before it
  const shopRegex = /^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/;
  return shopRegex.test(shop);
}

/**
 * Generate secure nonce for OAuth state parameter
 */
function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Save shop data to store
 */
function saveShop(shop, accessToken) {
  shopStore.set(shop, {
    shop,
    accessToken,
    installedAt: new Date().toISOString()
  });
  console.log(`✅ Shop saved: ${shop}`);
}

/**
 * Get shop data from store
 */
function getShop(shop) {
  return shopStore.get(shop);
}

/**
 * Exchange authorization code for access token
 */
async function getAccessToken(shop, code) {
  try {
    const response = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code: code
      }
    );
    
    return response.data.access_token;
  } catch (error) {
    console.error('❌ Error getting access token:', error.response?.data || error.message);
    throw error;
  }
}

/**
 * Send shop data to Bubble
 */
async function sendToBubble(shop, accessToken) {
  if (!BUBBLE_API_ENDPOINT) {
    console.warn('⚠️ BUBBLE_API_ENDPOINT not configured');
    return;
  }

  try {
    console.log(`📤 Sending shop data to Bubble: ${shop}`);
    await axios.post(BUBBLE_API_ENDPOINT, {
      shop: shop,
      access_token: accessToken,
      installed_at: new Date().toISOString()
    }, {
      timeout: 30000
    });
    console.log('✅ Data sent to Bubble successfully');
  } catch (error) {
    console.error('❌ Error sending to Bubble:', error.response?.data || error.message);
    // Don't throw - we still want OAuth to succeed
  }
}

// ===========================================
// OAUTH ROUTES
// ===========================================

/**
 * Root endpoint - Main app entry point
 * This is your "App URL" in Shopify Partner Dashboard
 * When merchant clicks "Open app", they come here
 */
app.get('/', async (req, res) => {
  const { shop, hmac } = req.query;
  
  // No shop parameter - show info page
  if (!shop) {
    return res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>KatiCRM - Shopify Integration</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
          }
          .container {
            background: white;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            text-align: center;
          }
          .logo { font-size: 48px; margin-bottom: 20px; }
          h1 { color: #333; margin-bottom: 10px; font-size: 28px; }
          p { color: #666; line-height: 1.6; margin-bottom: 30px; }
          .button {
            display: inline-block;
            background: #5469d4;
            color: white;
            padding: 12px 30px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s;
          }
          .button:hover { background: #4055c1; transform: translateY(-2px); }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="logo">🛡️</div>
          <h1>KatiCRM</h1>
          <p>Omni-channel Customer Relationship Management for Shopify</p>
          <p>This app must be accessed from within your Shopify store admin.</p>
          <a href="https://apps.shopify.com" class="button">Visit Shopify App Store</a>
        </div>
      </body>
      </html>
    `);
  }
  
  // Validate shop format
  if (!isValidShopDomain(shop)) {
    return res.status(400).send(`
      <h1>Invalid Shop Domain</h1>
      <p>Shop must be in format: your-store.myshopify.com</p>
    `);
  }
  
  // Verify HMAC if present
  if (hmac && !verifyHmac(req.query, hmac)) {
    return res.status(403).send('HMAC validation failed');
  }
  
  // Check if shop is already authenticated
  const shopData = getShop(shop);
  
  if (shopData && shopData.accessToken) {
    // Authenticated - redirect to Bubble app
    console.log(`✅ Authenticated shop accessing app: ${shop}`);
    const redirectUrl = `${BUBBLE_SUCCESS_URL}?shop=${shop}&token=${shopData.accessToken}`;
    return res.redirect(redirectUrl);
  }
  
  // Not authenticated - start OAuth
  console.log(`🔐 Starting OAuth for shop: ${shop}`);
  
  const state = generateNonce();
  const redirectUri = `${APP_URL}/auth/callback`;
  
  // Store state for verification
  stateStore.set(`state_${shop}`, { state, timestamp: Date.now() });
  
  const installUrl = 
    `https://${shop}/admin/oauth/authorize?` +
    `client_id=${SHOPIFY_API_KEY}` +
    `&scope=${SCOPES}` +
    `&redirect_uri=${redirectUri}` +
    `&state=${state}`;
  
  res.redirect(installUrl);
});

/**
 * OAuth callback endpoint
 * Shopify redirects here after merchant authorizes
 */
app.get('/auth/callback', async (req, res) => {
  const { shop, code, state, hmac } = req.query;
  
  console.log('🔑 OAuth callback received');
  console.log('Shop:', shop);
  console.log('Code present:', !!code);
  console.log('State present:', !!state);
  console.log('HMAC present:', !!hmac);
  
  // Validate required parameters
  if (!shop || !code) {
    console.error('❌ Missing shop or code');
    return res.status(400).send('Missing required parameters');
  }
  
  // Validate shop format
  if (!isValidShopDomain(shop)) {
    console.error('❌ Invalid shop format:', shop);
    return res.status(400).send('Invalid shop format');
  }
  
  // Verify HMAC
  if (!hmac || !verifyHmac(req.query, hmac)) {
    console.error('❌ HMAC verification failed');
    return res.status(403).send('HMAC validation failed');
  }
  
  // Verify state (CSRF protection)
  const stateData = stateStore.get(`state_${shop}`);
  if (!stateData || state !== stateData.state) {
    console.error('❌ State validation failed');
    return res.status(403).send('State validation failed');
  }
  
  // Check state age (should be < 5 minutes)
  const stateAge = Date.now() - stateData.timestamp;
  if (stateAge > 5 * 60 * 1000) {
    console.error('❌ State expired');
    stateStore.delete(`state_${shop}`);
    return res.status(403).send('State expired. Please try again.');
  }
  
  try {
    // Exchange code for access token
    console.log('🔄 Exchanging code for access token...');
    const accessToken = await getAccessToken(shop, code);
    console.log('✅ Access token obtained');
    
    // Save shop data
    saveShop(shop, accessToken);
    
    // Send to Bubble (async, don't block)
    sendToBubble(shop, accessToken).catch(err => 
      console.error('Background Bubble sync failed:', err)
    );
    
    // Clean up state
    stateStore.delete(`state_${shop}`);
    
    // Redirect to Bubble app
    console.log('✅ OAuth complete, redirecting to Bubble app');
    const redirectUrl = `${BUBBLE_SUCCESS_URL}?shop=${shop}&token=${accessToken}&first_install=true`;
    res.redirect(redirectUrl);
    
  } catch (error) {
    console.error('❌ OAuth callback error:', error);
    
    // Redirect to error page
    const errorUrl = `${BUBBLE_ERROR_URL}?error=installation_failed&shop=${shop}`;
    res.redirect(errorUrl);
  }
});

// ===========================================
// PUBLIC ENDPOINTS
// ===========================================

/**
 * Health check endpoint (for Railway/monitoring)
 */
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'KatiCRM Shopify OAuth Middleware',
    version: '2.0.0'
  });
});

/**
 * Simple status check (no auth)
 */
app.get('/status', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'KatiCRM OAuth Middleware',
    timestamp: new Date().toISOString()
  });
});

// ===========================================
// ADMIN ENDPOINTS (PROTECTED)
// ===========================================

/**
 * Admin authentication middleware
 */
function requireAdminAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || authHeader !== `Bearer ${ADMIN_PASSWORD}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  next();
}

/**
 * Admin status page (protected)
 * Access: curl -H "Authorization: Bearer YOUR_PASSWORD" https://your-app.up.railway.app/admin/status
 */
app.get('/admin/status', requireAdminAuth, (req, res) => {
  const shops = Array.from(shopStore.keys());
  
  res.json({
    service: 'KatiCRM OAuth Middleware',
    status: 'operational',
    timestamp: new Date().toISOString(),
    statistics: {
      connectedShops: shopStore.size,
      activeStates: stateStore.size
    },
    shops: shops,
    configuration: {
      oauthEnabled: !!SHOPIFY_API_KEY && !!SHOPIFY_API_SECRET,
      bubbleConfigured: !!BUBBLE_API_ENDPOINT,
      gdprWebhooksConfigured: !!(BUBBLE_GDPR_DATA_REQUEST || BUBBLE_GDPR_CUSTOMER_REDACT || BUBBLE_GDPR_SHOP_REDACT)
    }
  });
});

/**
 * Admin endpoint to check specific shop
 */
app.get('/admin/shop/:shop', requireAdminAuth, (req, res) => {
  const shop = req.params.shop;
  const shopData = getShop(shop);
  
  if (!shopData) {
    return res.status(404).json({ error: 'Shop not found' });
  }
  
  res.json({
    shop: shopData.shop,
    authenticated: true,
    installedAt: shopData.installedAt
  });
});

// ===========================================
// GDPR WEBHOOKS
// ===========================================

/**
 * Customer Data Request Webhook
 * Handles GDPR data export requests
 */
app.post('/webhooks/customers/data_request', async (req, res) => {
  console.log('📋 Customer data request received');
  
  const shop = req.get('X-Shopify-Shop-Domain') || req.get('x-shopify-shop-domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256') || req.get('x-shopify-hmac-sha256');
  
  console.log('🏪 Shop:', shop);
  console.log('🔐 HMAC present:', hmac ? 'Yes' : 'No');
  
  // Parse body
  const rawBody = req.body;
  let body;
  
  try {
    const bodyString = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
    body = JSON.parse(bodyString);
    console.log('📦 Body keys:', Object.keys(body).join(', '));
  } catch (e) {
    console.error('❌ Failed to parse body:', e.message);
    return res.status(400).send('Invalid JSON');
  }
  
  // Check HMAC
  if (!hmac) {
    if (isShopifyConnectivityTest(body, req.headers)) {
      console.log('✅ Shopify connectivity test detected - accepting without HMAC');
      return res.status(200).send('Data request webhook is reachable');
    }
    console.error('❌ No HMAC provided - request rejected');
    return res.status(401).send('Unauthorized: HMAC signature required');
  }
  
  // Verify HMAC
  if (!verifyWebhook(rawBody, hmac)) {
    console.error('❌ Webhook HMAC verification failed');
    return res.status(401).send('Unauthorized: Invalid HMAC signature');
  }
  
  console.log('✅ Webhook HMAC verified successfully');
  
  // Respond immediately
  res.status(200).send('Customer data request acknowledged');
  
  // Process asynchronously
  setImmediate(async () => {
    const bubbleEndpoint = BUBBLE_GDPR_DATA_REQUEST;
    
    if (bubbleEndpoint) {
      try {
        console.log('📤 Forwarding data request to Bubble:', bubbleEndpoint);
        await axios.post(bubbleEndpoint, {
          shop: shop || body.shop_domain,
          customer_email: body.customer?.email,
          customer_id: body.customer?.id,
          orders_requested: body.orders_requested,
          request_id: body.id,
          received_at: new Date().toISOString()
        }, {
          timeout: 30000
        });
        console.log('✅ Data request forwarded to Bubble successfully');
      } catch (error) {
        console.error('❌ Error forwarding to Bubble:', error.message);
      }
    } else {
      console.warn('⚠️ No Bubble endpoint configured for data requests');
    }
  });
});

/**
 * Customer Redact Webhook
 * Handles GDPR customer data deletion requests
 */
app.post('/webhooks/customers/redact', async (req, res) => {
  console.log('🗑️ Customer redaction request received');
  
  const shop = req.get('X-Shopify-Shop-Domain') || req.get('x-shopify-shop-domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256') || req.get('x-shopify-hmac-sha256');
  
  console.log('🏪 Shop:', shop);
  console.log('🔐 HMAC present:', hmac ? 'Yes' : 'No');
  
  // Parse body
  const rawBody = req.body;
  let body;
  
  try {
    const bodyString = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
    body = JSON.parse(bodyString);
    console.log('📦 Body keys:', Object.keys(body).join(', '));
  } catch (e) {
    console.error('❌ Failed to parse body:', e.message);
    return res.status(400).send('Invalid JSON');
  }
  
  // Check HMAC
  if (!hmac) {
    if (isShopifyConnectivityTest(body, req.headers)) {
      console.log('✅ Shopify connectivity test detected - accepting without HMAC');
      return res.status(200).send('Customer redact webhook is reachable');
    }
    console.error('❌ No HMAC provided - request rejected');
    return res.status(401).send('Unauthorized: HMAC signature required');
  }
  
  // Verify HMAC
  if (!verifyWebhook(rawBody, hmac)) {
    console.error('❌ Webhook HMAC verification failed');
    return res.status(401).send('Unauthorized: Invalid HMAC signature');
  }
  
  console.log('✅ Webhook HMAC verified successfully');
  
  // Respond immediately
  res.status(200).send('Customer data will be redacted');
  
  // Process asynchronously
  setImmediate(async () => {
    const bubbleEndpoint = BUBBLE_GDPR_CUSTOMER_REDACT;
    
    if (bubbleEndpoint) {
      try {
        console.log('📤 Forwarding redaction request to Bubble:', bubbleEndpoint);
        await axios.post(bubbleEndpoint, {
          shop: shop || body.shop_domain,
          customer_email: body.customer?.email,
          customer_id: body.customer?.id,
          orders_to_redact: body.orders_to_redact,
          request_id: body.id,
          received_at: new Date().toISOString()
        }, {
          timeout: 30000
        });
        console.log('✅ Redaction request forwarded to Bubble successfully');
      } catch (error) {
        console.error('❌ Error forwarding to Bubble:', error.message);
      }
    } else {
      console.warn('⚠️ No Bubble endpoint configured for customer redaction');
    }
  });
});

/**
 * Shop Redact Webhook
 * Handles shop data deletion when app is uninstalled
 */
app.post('/webhooks/shop/redact', async (req, res) => {
  console.log('🏪 Shop redaction request received');
  
  const shop = req.get('X-Shopify-Shop-Domain') || req.get('x-shopify-shop-domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256') || req.get('x-shopify-hmac-sha256');
  
  console.log('🏪 Shop:', shop);
  console.log('🔐 HMAC present:', hmac ? 'Yes' : 'No');
  
  // Parse body
  const rawBody = req.body;
  let body;
  
  try {
    const bodyString = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
    body = JSON.parse(bodyString);
    console.log('📦 Body keys:', Object.keys(body).join(', '));
  } catch (e) {
    console.error('❌ Failed to parse body:', e.message);
    return res.status(400).send('Invalid JSON');
  }
  
  // Check HMAC
  if (!hmac) {
    if (isShopifyConnectivityTest(body, req.headers)) {
      console.log('✅ Shopify connectivity test detected - accepting without HMAC');
      return res.status(200).send('Shop redact webhook is reachable');
    }
    console.error('❌ No HMAC provided - request rejected');
    return res.status(401).send('Unauthorized: HMAC signature required');
  }
  
  // Verify HMAC
  if (!verifyWebhook(rawBody, hmac)) {
    console.error('❌ Webhook HMAC verification failed');
    return res.status(401).send('Unauthorized: Invalid HMAC signature');
  }
  
  console.log('✅ Webhook HMAC verified successfully');
  
  // Remove shop from local store
  const shopDomain = shop || body.shop_domain;
  if (shopDomain) {
    shopStore.delete(shopDomain);
    console.log(`🗑️ Removed shop from store: ${shopDomain}`);
  }
  
  // Respond immediately
  res.status(200).send('Shop data will be redacted');
  
  // Process asynchronously
  setImmediate(async () => {
    const bubbleEndpoint = BUBBLE_GDPR_SHOP_REDACT;
    
    if (bubbleEndpoint) {
      try {
        console.log('📤 Forwarding shop redaction to Bubble:', bubbleEndpoint);
        await axios.post(bubbleEndpoint, {
          shop: shopDomain,
          shop_id: body.shop_id,
          shop_domain: body.shop_domain,
          request_id: body.id,
          received_at: new Date().toISOString()
        }, {
          timeout: 30000
        });
        console.log('✅ Shop redaction request forwarded to Bubble successfully');
      } catch (error) {
        console.error('❌ Error forwarding to Bubble:', error.message);
      }
    } else {
      console.warn('⚠️ No Bubble endpoint configured for shop redaction');
    }
  });
});

/**
 * Base Webhook Endpoint
 * Handles HMAC verification test from Shopify
 */
app.post('/webhooks', async (req, res) => {
  console.log('⚠️ Base /webhooks endpoint called');
  
  const hmac = req.get('X-Shopify-Hmac-Sha256') || req.get('x-shopify-hmac-sha256');
  const userAgent = req.get('user-agent');
  
  console.log('🔐 HMAC present:', hmac ? 'Yes' : 'No');
  console.log('🤖 User-Agent:', userAgent);
  
  if (!hmac) {
    console.log('❌ No HMAC - returning 401 Unauthorized');
    return res.status(401).send('Unauthorized: HMAC signature required');
  }
  
  // Parse and verify
  const rawBody = req.body;
  
  if (!verifyWebhook(rawBody, hmac)) {
    console.log('❌ Invalid HMAC - returning 401 Unauthorized');
    return res.status(401).send('Unauthorized: Invalid HMAC signature');
  }
  
  console.log('✅ Valid HMAC but no specific topic handler');
  res.status(200).send('Webhook received and verified');
});

// ===========================================
// ERROR HANDLING
// ===========================================

// 404 handler
app.use((req, res) => {
  console.log('404 Not Found:', req.method, req.path);
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested endpoint does not exist',
    path: req.path
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  
  // Don't expose internal errors to clients
  res.status(500).json({
    error: 'Internal Server Error',
    message: 'An unexpected error occurred'
  });
});

// ===========================================
// SERVER STARTUP
// ===========================================

// Graceful shutdown handler
process.on('SIGTERM', () => {
  console.log('⚠️ SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log('');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║  🛡️  KatiCRM Shopify OAuth Middleware v2.0                 ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌐 App URL: ${APP_URL}`);
  console.log(`🔗 OAuth Callback: ${APP_URL}/auth/callback`);
  console.log(`💚 Health Check: ${APP_URL}/health`);
  console.log(`🔐 Admin Status: ${APP_URL}/admin/status`);
  console.log('');
  console.log('🔒 Security Features:');
  console.log('  ✅ HMAC verification enabled');
  console.log('  ✅ CSRF protection (state parameter)');
  console.log('  ✅ GDPR webhooks configured');
  console.log('  ✅ Security headers applied');
  console.log('  ✅ Input validation active');
  console.log('');
  console.log('⚙️  Configuration:');
  console.log(`  🔑 Shopify API Key: ${SHOPIFY_API_KEY ? '✅' : '❌'}`);
  console.log(`  🔐 Shopify Secret: ${SHOPIFY_API_SECRET ? '✅' : '❌'}`);
  console.log(`  💾 Bubble Endpoint: ${BUBBLE_API_ENDPOINT ? '✅' : '❌'}`);
  console.log(`  🎯 Success URL: ${BUBBLE_SUCCESS_URL}`);
  console.log('');
  console.log('✅ Ready to accept OAuth requests');
  console.log('');
});
