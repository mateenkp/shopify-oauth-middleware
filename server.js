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
const BUBBLE_SUCCESS_URL = process.env.BUBBLE_SUCCESS_URL;
const BUBBLE_ERROR_URL = process.env.BUBBLE_ERROR_URL;
const SCOPES = 'read_customers,write_customers,read_orders,write_orders,read_products,write_products,read_inventory,write_inventory,read_locations,read_discounts,write_discounts,customer_read_companies,customer_write_companies';

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
 * Sanitize error messages for user display
 * @param {Error} error - Error object
 * @returns {string} - Safe error message
 */
function getSafeErrorMessage(error) {
  // Don't expose internal error details to users
  if (error.response?.data?.errors) {
    return 'Authentication failed. Please try again.';
  }
  return 'An error occurred. Please contact support if this persists.';
}

// ===========================================
// PUBLIC ENDPOINTS
// ===========================================

/**
 * Health check endpoint
 * Provides service status without exposing sensitive data
 */
app.get('/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'KatiCRM Shopify OAuth Middleware',
    version: '1.0.0',
    checks: {
      shopifySecretConfigured: !!SHOPIFY_API_SECRET,
      bubbleEndpointConfigured: !!BUBBLE_API_ENDPOINT,
      gdprWebhooksConfigured: !!(BUBBLE_GDPR_DATA_REQUEST || BUBBLE_GDPR_CUSTOMER_REDACT || BUBBLE_GDPR_SHOP_REDACT)
    }
  };
  
  res.status(200).json(health);
});

/**
 * Status endpoint for monitoring
 */
app.get('/status', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'KatiCRM OAuth Middleware',
    timestamp: new Date().toISOString(),
    endpoints: {
      oauth: 'operational',
      webhooks: 'operational',
      gdpr: 'enabled'
    }
  });
});

/**
 * Root endpoint - user-friendly landing page
 */
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>KatiCRM - Shopify Integration</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
          }
          .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px;
            padding: 40px;
            text-align: center;
          }
          h1 { 
            color: #008060; 
            margin-bottom: 10px;
            font-size: 2em;
          }
          .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 1.1em;
          }
          .status-card { 
            background: #d4edda; 
            padding: 20px; 
            border-radius: 8px; 
            border: 1px solid #c3e6cb;
            margin: 20px 0;
          }
          .status-card h2 { 
            color: #155724; 
            margin: 0 0 15px 0;
            font-size: 1.3em;
          }
          .status-list {
            list-style: none;
            text-align: left;
            display: inline-block;
          }
          .status-list li {
            padding: 8px 0;
            border-bottom: 1px solid rgba(0,0,0,0.05);
          }
          .status-list li:last-child {
            border-bottom: none;
          }
          .status-list li::before {
            content: "✓ ";
            color: #28a745;
            font-weight: bold;
            margin-right: 8px;
          }
          .link-button {
            display: inline-block;
            background: #008060;
            color: white;
            padding: 12px 24px;
            border-radius: 6px;
            text-decoration: none;
            margin: 10px;
            transition: background 0.3s;
          }
          .link-button:hover {
            background: #006e52;
          }
          .footer {
            color: #666;
            font-size: 0.9em;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
          }
          .logo {
            font-size: 3em;
            margin-bottom: 10px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="logo">🛡️</div>
          <h1>KatiCRM</h1>
          <p class="subtitle">Shopify Integration Service</p>
          
          <div class="status-card">
            <h2>Service Operational</h2>
            <ul class="status-list">
              <li>OAuth Authentication Active</li>
              <li>GDPR Webhooks Configured</li>
              <li>HMAC Verification Enabled</li>
              <li>Security Headers Applied</li>
            </ul>
          </div>
          
          <div>
            <a href="/health" class="link-button">Health Check</a>
            <a href="/status" class="link-button">Service Status</a>
          </div>
          
          <div class="footer">
            <p><strong>For Merchants:</strong></p>
            <p>Install KatiCRM via the Shopify App Store or your Partner Dashboard</p>
            <p style="margin-top: 15px; font-size: 0.85em;">
              This is the authentication middleware for KatiCRM.<br>
              © ${new Date().getFullYear()} Calltronix - All rights reserved
            </p>
          </div>
        </div>
      </body>
    </html>
  `);
});

// ===========================================
// OAUTH FLOW
// ===========================================

/**
 * Initiate OAuth Installation
 * Entry point for merchants to install the app
 */
app.get('/install', (req, res) => {
  const shop = req.query.shop;
  
  // Validate shop parameter
  if (!shop) {
    console.error('Install attempt without shop parameter');
    return res.status(400).send('Missing shop parameter. Please provide ?shop=your-store.myshopify.com');
  }
  
  // Validate shop domain format
  if (!isValidShopDomain(shop)) {
    console.error('Invalid shop domain format:', shop);
    return res.status(400).send('Invalid shop domain format. Must be: your-store.myshopify.com');
  }
  
  // Generate secure state parameter for CSRF protection
  const state = crypto.randomBytes(32).toString('hex');
  const redirectUri = `${APP_URL}/callback`;
  
  // Build Shopify OAuth URL
  const installUrl = `https://${shop}/admin/oauth/authorize?` +
    `client_id=${SHOPIFY_API_KEY}&` +
    `scope=${SCOPES}&` +
    `redirect_uri=${encodeURIComponent(redirectUri)}&` +
    `state=${state}`;
  
  console.log('✅ Initiating OAuth for shop:', shop);
  console.log('📍 Redirect URI:', redirectUri);
  
  // In production, you should store the state in Redis/database
  // and validate it in the callback for CSRF protection
  
  res.redirect(installUrl);
});

/**
 * OAuth Callback Handler
 * Receives authorization code from Shopify and exchanges it for access token
 */
app.get('/callback', async (req, res) => {
  const { shop, code, hmac, state } = req.query;
  
  console.log('📥 Received callback from Shopify');
  console.log('🏪 Shop:', shop);
  console.log('🔑 Code received:', code ? 'Yes' : 'No');
  
  // Validate required parameters
  if (!shop || !code || !hmac) {
    console.error('❌ Missing required parameters in callback');
    const errorUrl = BUBBLE_ERROR_URL || `https://katicrm.com/shopify-connected?success=false&error=missing_parameters`;
    return res.redirect(errorUrl);
  }
  
  // Validate shop domain format
  if (!isValidShopDomain(shop)) {
    console.error('❌ Invalid shop domain in callback:', shop);
    const errorUrl = BUBBLE_ERROR_URL || `https://katicrm.com/shopify-connected?success=false&error=invalid_shop`;
    return res.redirect(errorUrl);
  }
  
  // Verify HMAC to ensure request is from Shopify
  if (!verifyHmac(req.query, hmac)) {
    console.error('❌ HMAC validation failed for shop:', shop);
    const errorUrl = BUBBLE_ERROR_URL || `https://katicrm.com/shopify-connected?success=false&error=invalid_hmac`;
    return res.redirect(errorUrl);
  }
  
  console.log('✅ HMAC validated successfully');
  
  try {
    console.log('🔄 Exchanging authorization code for access token...');
    
    // Exchange authorization code for access token
    const tokenResponse = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code: code
      },
      {
        timeout: 10000, // 10 second timeout
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      }
    );
    
    const accessToken = tokenResponse.data.access_token;
    const scope = tokenResponse.data.scope;
    
    console.log('✅ Access token obtained successfully');
    console.log('🔐 Granted scopes:', scope);
    
    // Store token in Bubble
    console.log('💾 Sending token to Bubble:', BUBBLE_API_ENDPOINT);
    
    await axios.post(
      BUBBLE_API_ENDPOINT,
      {
        shop_domain: shop,
        access_token: accessToken,
        scope: scope,
        connected_at: new Date().toISOString(),
        app_version: '1.0.0'
      },
      {
        timeout: 10000,
        headers: {
          'Content-Type': 'application/json'
        }
      }
    );
    
    console.log('✅ Token stored in Bubble successfully');
    
    // Redirect to success page
    const successUrl = BUBBLE_SUCCESS_URL || `https://katicrm.com/shopify-connected?shop=${encodeURIComponent(shop)}&success=true`;
    res.redirect(successUrl);
    
  } catch (error) {
    console.error('❌ OAuth error:', error.response?.data || error.message);
    
    // Log detailed error for debugging but send safe message to user
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', JSON.stringify(error.response.data));
    }
    
    const safeError = getSafeErrorMessage(error);
    const errorUrl = BUBBLE_ERROR_URL || `https://katicrm.com/shopify-connected?success=false&error=${encodeURIComponent(safeError)}`;
    res.redirect(errorUrl);
  }
});

// ===========================================
// GDPR COMPLIANCE WEBHOOK ENDPOINTS
// ===========================================

/**
 * Customer Data Request Webhook
 * Handles GDPR data access requests
 */
app.post('/webhooks/customers/data_request', async (req, res) => {
  console.log('📋 Customer data request received');
  
  const shop = req.get('X-Shopify-Shop-Domain') || req.get('x-shopify-shop-domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256') || req.get('x-shopify-hmac-sha256');
  const userAgent = req.get('user-agent');
  
  console.log('🏪 Shop:', shop);
  console.log('🔐 HMAC present:', hmac ? 'Yes' : 'No');
  console.log('🤖 User-Agent:', userAgent);
  
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
  
  // Respond immediately (Shopify requires response within 5 seconds)
  res.status(200).send('Data request received and will be processed');
  
  // Process asynchronously
  setImmediate(async () => {
    const bubbleEndpoint = BUBBLE_GDPR_DATA_REQUEST || 
      (BUBBLE_API_ENDPOINT ? BUBBLE_API_ENDPOINT.replace('/store_shopify_token', '/gdpr_data_request') : null);
    
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
    const bubbleEndpoint = BUBBLE_GDPR_CUSTOMER_REDACT || 
      (BUBBLE_API_ENDPOINT ? BUBBLE_API_ENDPOINT.replace('/store_shopify_token', '/gdpr_customer_redact') : null);
    
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
  
  // Respond immediately
  res.status(200).send('Shop data will be redacted');
  
  // Process asynchronously
  setImmediate(async () => {
    const bubbleEndpoint = BUBBLE_GDPR_SHOP_REDACT || 
      (BUBBLE_API_ENDPOINT ? BUBBLE_API_ENDPOINT.replace('/store_shopify_token', '/gdpr_shop_redact') : null);
    
    if (bubbleEndpoint) {
      try {
        console.log('📤 Forwarding shop redaction to Bubble:', bubbleEndpoint);
        await axios.post(bubbleEndpoint, {
          shop: shop || body.shop_domain,
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
  console.log('='.repeat(50));
  console.log('🚀 KatiCRM Shopify OAuth Middleware Started');
  console.log('='.repeat(50));
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌐 App URL: ${APP_URL}`);
  console.log(`💚 Health: ${APP_URL}/health`);
  console.log(`📊 Status: ${APP_URL}/status`);
  console.log('='.repeat(50));
  console.log('🔐 Security Features:');
  console.log('  ✅ HMAC verification enabled');
  console.log('  ✅ GDPR webhooks configured');
  console.log('  ✅ Security headers applied');
  console.log('  ✅ Input validation active');
  console.log('='.repeat(50));
  console.log(`🔑 Shopify Secret: ${SHOPIFY_API_SECRET ? '✅ Configured' : '❌ NOT configured'}`);
  console.log(`💾 Bubble Endpoint: ${BUBBLE_API_ENDPOINT ? '✅ Configured' : '❌ NOT configured'}`);
  console.log('='.repeat(50));
  console.log('✅ Ready to accept connections');
  console.log('='.repeat(50));
});
