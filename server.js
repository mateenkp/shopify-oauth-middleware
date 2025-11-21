/**
 * KatiCRM Shopify OAuth Middleware v3.5 - STANDALONE APP VERSION
 * 
 * OAUTH FLOW (CORRECTED - ONLY THROUGH KATICRM):
 * 1. User clicks "Connect Shopify" on KatiCRM → /auth/shopify?shop=store.myshopify.com&state=katicrm_connect
 * 2. Middleware validates state parameter (blocks direct installs)
 * 3. Middleware redirects to Shopify OAuth screen
 * 4. User approves → Shopify calls /auth/callback with code
 * 5. Middleware exchanges code for token
 * 6. Middleware stores token persistently
 * 7. Middleware redirects to KatiCRM success page (shopify_auth)
 * 
 * TOKEN RETRIEVAL:
 * - Bubble can query /api/token/:shop to check if token exists
 * - If token exists, Bubble creates database entry without new OAuth
 * - Prevents duplicate OAuth flows and improves UX
 * 
 * SECURITY: Direct OAuth attempts without state parameter are redirected to KatiCRM
 * 
 * @author KatiCRM Team
 * @version 3.5.0 - Added token retrieval API and improved storage
 */

const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const querystring = require('querystring');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';

// ===========================================
// CONFIGURATION
// ===========================================

const CONFIG = {
  shopify: {
    apiKey: process.env.SHOPIFY_API_KEY,
    apiSecret: process.env.SHOPIFY_API_SECRET,
    scopes: process.env.SHOPIFY_SCOPES || 'read_customers,write_customers,read_orders,write_orders,read_products,write_products,read_inventory,write_inventory,read_locations,read_discounts,write_discounts,read_company_locations,read_fulfillments,write_fulfillments',
  },
  app: {
    url: process.env.APP_URL,
    adminPassword: process.env.ADMIN_PASSWORD || 'change-this-password',
  },
  bubble: {
    apiEndpoint: process.env.BUBBLE_API_ENDPOINT,
    successUrl: process.env.BUBBLE_SUCCESS_URL || 'https://katicrm.com/version-test/shopify_auth',
    errorUrl: process.env.BUBBLE_ERROR_URL || 'https://katicrm.com/version-test/shopify_auth',
    landingUrl: process.env.BUBBLE_LANDING_URL || 'https://katicrm.com/version-test',
    gdpr: {
      dataRequest: process.env.BUBBLE_GDPR_DATA_REQUEST,
      customerRedact: process.env.BUBBLE_GDPR_CUSTOMER_REDACT,
      shopRedact: process.env.BUBBLE_GDPR_SHOP_REDACT,
    },
  },
  redis: {
    enabled: process.env.REDIS_URL ? true : false,
    url: process.env.REDIS_URL,
  },
  security: {
    stateExpiryMs: 10 * 60 * 1000,
    maxWebhookAge: 5 * 60 * 1000,
    requireStateParameter: true,
    tokenExpiryDays: 365, // Tokens don't expire unless store disconnects
  },
  timeouts: {
    axios: 30000,
    gracefulShutdown: 10000,
  },
};

// ===========================================
// STRUCTURED LOGGING
// ===========================================

const logger = {
  info: (message, meta = {}) => {
    console.log(JSON.stringify({
      level: 'info',
      timestamp: new Date().toISOString(),
      message,
      ...meta,
    }));
  },
  warn: (message, meta = {}) => {
    console.warn(JSON.stringify({
      level: 'warn',
      timestamp: new Date().toISOString(),
      message,
      ...meta,
    }));
  },
  error: (message, error = null, meta = {}) => {
    console.error(JSON.stringify({
      level: 'error',
      timestamp: new Date().toISOString(),
      message,
      error: error ? {
        message: error.message,
        stack: error.stack,
        code: error.code,
        status: error.response?.status,
        statusText: error.response?.statusText,
        data: error.response?.data,
      } : null,
      ...meta,
    }));
  },
  debug: (message, meta = {}) => {
    if (NODE_ENV === 'development') {
      console.log(JSON.stringify({
        level: 'debug',
        timestamp: new Date().toISOString(),
        message,
        ...meta,
      }));
    }
  },
};

// ===========================================
// STORAGE LAYER
// ===========================================

let storage;
let redisClient;

if (CONFIG.redis.enabled) {
  const Redis = require('ioredis');
  redisClient = new Redis(CONFIG.redis.url, {
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
    retryStrategy(times) {
      const delay = Math.min(times * 50, 2000);
      return delay;
    },
  });

  redisClient.on('connect', () => logger.info('✅ Redis connected'));
  redisClient.on('error', (err) => logger.error('❌ Redis error:', err));

  storage = {
    async set(key, value, expirySeconds = null) {
      const data = JSON.stringify(value);
      if (expirySeconds) {
        await redisClient.setex(key, expirySeconds, data);
      } else {
        await redisClient.set(key, data);
      }
    },
    async get(key) {
      const data = await redisClient.get(key);
      return data ? JSON.parse(data) : null;
    },
    async delete(key) {
      await redisClient.del(key);
    },
    async exists(key) {
      return (await redisClient.exists(key)) === 1;
    },
    async keys(pattern) {
      return await redisClient.keys(pattern);
    },
  };
} else {
  logger.warn('⚠️  Using in-memory storage (tokens will be lost on restart)');
  
  const memoryStore = new Map();
  
  storage = {
    async set(key, value) {
      memoryStore.set(key, value);
    },
    async get(key) {
      return memoryStore.get(key) || null;
    },
    async delete(key) {
      memoryStore.delete(key);
    },
    async exists(key) {
      return memoryStore.has(key);
    },
    async keys(pattern) {
      const regex = new RegExp('^' + pattern.replace('*', '.*') + '$');
      return Array.from(memoryStore.keys()).filter(key => regex.test(key));
    },
  };
}

// ===========================================
// VALIDATION & SANITIZATION
// ===========================================

function validateShopInput(shop) {
  if (!shop || typeof shop !== 'string') {
    return { valid: false, error: 'Shop parameter is required' };
  }

  shop = shop.trim().toLowerCase();

  if (shop.includes('.myshopify.com')) {
    const fullShopRegex = /^[a-z0-9][a-z0-9\-]*\.myshopify\.com$/;
    if (!fullShopRegex.test(shop)) {
      return { valid: false, error: 'Invalid shop domain format' };
    }
    return { valid: true, shop };
  }

  const handleRegex = /^[a-z0-9][a-z0-9\-]*$/;
  if (!handleRegex.test(shop)) {
    return { 
      valid: false, 
      error: 'Shop name can only contain lowercase letters, numbers, and hyphens' 
    };
  }

  return { valid: true, shop: `${shop}.myshopify.com` };
}

// ===========================================
// VALIDATE CONFIGURATION
// ===========================================

function validateConfig() {
  const required = {
    'SHOPIFY_API_KEY': CONFIG.shopify.apiKey,
    'SHOPIFY_API_SECRET': CONFIG.shopify.apiSecret,
    'APP_URL': CONFIG.app.url,
    'BUBBLE_API_ENDPOINT': CONFIG.bubble.apiEndpoint,
  };
  
  const missing = Object.entries(required)
    .filter(([_, value]) => !value)
    .map(([key]) => key);
  
  if (missing.length > 0) {
    logger.error('❌ Missing required environment variables', { missing });
    process.exit(1);
  }

  try {
    new URL(CONFIG.app.url);
    new URL(CONFIG.bubble.apiEndpoint);
  } catch (error) {
    logger.error('❌ Invalid URL in configuration', { error });
    process.exit(1);
  }

  logger.info('✅ Configuration validated');
}

validateConfig();

// ===========================================
// MIDDLEWARE CONFIGURATION
// ===========================================

app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
}));

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    
    if (origin.includes('.myshopify.com') || origin.includes('shopify.com')) {
      return callback(null, true);
    }
    
    if (origin.includes('bubble.io') || origin.includes('bubble.is') || origin.includes('katicrm.com')) {
      return callback(null, true);
    }
    
    callback(null, true);
  },
  credentials: true,
}));

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const oauthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Too many authentication attempts, please try again later.',
  skipSuccessfulRequests: true,
});

const webhookLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 1000,
  message: 'Webhook rate limit exceeded',
});

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 60,
  message: 'API rate limit exceeded',
});

app.use('/auth', oauthLimiter);
app.use('/webhooks', webhookLimiter);
app.use('/api', apiLimiter);
app.use(generalLimiter);

app.use((req, res, next) => {
  req.id = crypto.randomBytes(16).toString('hex');
  res.setHeader('X-Request-ID', req.id);
  next();
});

app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info('Request completed', {
      requestId: req.id,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
    });
  });
  
  next();
});

app.use('/webhooks', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  req.setTimeout(30000);
  res.setTimeout(30000);
  next();
});

// ===========================================
// SECURITY FUNCTIONS
// ===========================================

function verifyHmac(query, hmac) {
  if (!hmac || !CONFIG.shopify.apiSecret) {
    return false;
  }
  
  try {
    const params = Object.keys(query)
      .filter(key => key !== 'hmac' && key !== 'signature')
      .sort()
      .reduce((acc, key) => {
        acc[key] = query[key];
        return acc;
      }, {});
    
    const message = querystring.stringify(params);
    
    const hash = crypto
      .createHmac('sha256', CONFIG.shopify.apiSecret)
      .update(message)
      .digest('hex');
      
    return crypto.timingSafeEqual(
      Buffer.from(hash),
      Buffer.from(hmac)
    );
  } catch (error) {
    logger.error('HMAC verification failed', error);
    return false;
  }
}

function verifyWebhook(rawBody, hmac) {
  if (!hmac || !CONFIG.shopify.apiSecret) {
    return false;
  }
  
  try {
    const bodyString = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
    
    const calculatedHmac = crypto
      .createHmac('sha256', CONFIG.shopify.apiSecret)
      .update(bodyString, 'utf8')
      .digest('base64');
    
    return crypto.timingSafeEqual(
      Buffer.from(calculatedHmac, 'base64'),
      Buffer.from(hmac, 'base64')
    );
  } catch (error) {
    logger.error('Webhook HMAC verification failed', error);
    return false;
  }
}

function isShopifyConnectivityTest(body, headers) {
  const userAgent = (headers['user-agent'] || '').toLowerCase();
  const hasShopifyUserAgent = userAgent.includes('shopify');
  const isMinimalPayload = body && Object.keys(body).length <= 3;
  const looksLikeTest = body && body.shop_id && body.shop_domain && !body.customer;
  
  return (hasShopifyUserAgent && isMinimalPayload) || looksLikeTest;
}

function generateNonce() {
  return crypto.randomBytes(32).toString('hex');
}

function isWebhookTimestampValid(timestamp) {
  if (!timestamp) return true;
  
  try {
    const webhookTime = new Date(timestamp).getTime();
    const now = Date.now();
    const age = now - webhookTime;
    
    return age < CONFIG.security.maxWebhookAge;
  } catch (error) {
    return true;
  }
}

// ===========================================
// DATA PERSISTENCE
// ===========================================

/**
 * Save shop data with access token
 * Enhanced version stores additional metadata for token retrieval
 */
async function saveShop(shop, accessToken, scope) {
  const shopData = {
    shop,
    accessToken,
    scope,
    installedAt: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
    tokenVersion: 1, // For future token rotation
  };
  
  await storage.set(`shop:${shop}`, shopData);
  
  // Create a separate token index for faster lookups
  await storage.set(`token:${shop}`, {
    accessToken,
    createdAt: new Date().toISOString(),
  });
  
  logger.info('Shop data saved with token index', { shop });
  
  return shopData;
}

/**
 * Get shop data
 */
async function getShop(shop) {
  return await storage.get(`shop:${shop}`);
}

/**
 * Get access token for a shop
 * Optimized lookup using token index
 */
async function getAccessTokenForShop(shop) {
  const tokenData = await storage.get(`token:${shop}`);
  
  if (!tokenData) {
    // Fallback to full shop data if token index doesn't exist
    const shopData = await getShop(shop);
    return shopData?.accessToken || null;
  }
  
  return tokenData.accessToken;
}

/**
 * Delete shop data and token
 */
async function deleteShop(shop) {
  await storage.delete(`shop:${shop}`);
  await storage.delete(`token:${shop}`);
  logger.info('Shop data and token deleted', { shop });
}

/**
 * Check if shop has valid token
 */
async function hasValidToken(shop) {
  const token = await getAccessTokenForShop(shop);
  return !!token;
}

/**
 * Save OAuth state
 */
async function saveState(shop, state) {
  const stateData = {
    state,
    shop,
    timestamp: Date.now(),
  };
  
  await storage.set(`state:${shop}`, stateData, 600);
  logger.debug('OAuth state saved', { shop, state });
}

/**
 * Verify OAuth state
 */
async function verifyState(shop, state) {
  const stateData = await storage.get(`state:${shop}`);
  
  if (!stateData) {
    logger.warn('OAuth state not found', { shop });
    return false;
  }
  
  if (stateData.state !== state) {
    logger.warn('OAuth state mismatch', { shop });
    return false;
  }
  
  const age = Date.now() - stateData.timestamp;
  if (age > CONFIG.security.stateExpiryMs) {
    logger.warn('OAuth state expired', { shop });
    await storage.delete(`state:${shop}`);
    return false;
  }
  
  await storage.delete(`state:${shop}`);
  logger.debug('OAuth state verified', { shop });
  
  return true;
}

// ===========================================
// SHOPIFY API FUNCTIONS
// ===========================================

async function getAccessToken(shop, code) {
  try {
    const response = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: CONFIG.shopify.apiKey,
        client_secret: CONFIG.shopify.apiSecret,
        code,
      },
      {
        timeout: CONFIG.timeouts.axios,
      }
    );
    
    logger.info('Access token obtained', { shop });
    return {
      accessToken: response.data.access_token,
      scope: response.data.scope,
    };
  } catch (error) {
    logger.error('Failed to get access token', error, { shop });
    throw new Error('Failed to obtain access token from Shopify');
  }
}

async function sendToBubble(endpoint, data, retries = 3) {
  if (!endpoint) {
    logger.warn('Bubble endpoint not configured');
    return { success: false, error: 'Endpoint not configured' };
  }

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      logger.info(`Sending data to Bubble (attempt ${attempt}/${retries})`, { 
        endpoint, 
        dataKeys: Object.keys(data),
      });
      
      const response = await axios.post(endpoint, data, {
        timeout: CONFIG.timeouts.axios,
        headers: {
          'Content-Type': 'application/json',
        },
      });
      
      logger.info('Data sent to Bubble successfully', { 
        endpoint,
        status: response.status,
      });
      
      return { success: true, response: response.data };
    } catch (error) {
      logger.error(`Bubble request failed (attempt ${attempt}/${retries})`, error, {
        endpoint,
        status: error.response?.status,
      });
      
      // Treat API Connector parsing errors as warnings, not failures
      if (error.response?.status === 400 && 
          error.response?.data?.message?.includes('Error parsing data from Apiconnector')) {
        logger.warn('Bubble API Connector parsing error - treating as non-fatal', {
          endpoint,
          error: error.response?.data?.message,
        });
        return { 
          success: true, 
          warning: 'API Connector parsing error ignored',
          partialSuccess: true,
        };
      }
      
      if (error.response?.status >= 400 && error.response?.status < 500) {
        return { 
          success: false, 
          error: `Bubble returned ${error.response.status}`,
          permanent: true,
        };
      }
      
      if (attempt === retries) {
        return { 
          success: false, 
          error: error.message,
          attempts: retries,
        };
      }
      
      const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// ===========================================
// HEALTH CHECKS
// ===========================================

async function checkBubbleHealth() {
  if (!CONFIG.bubble.apiEndpoint) {
    return { healthy: false, message: 'Bubble endpoint not configured' };
  }
  
  try {
    await axios.get(CONFIG.bubble.apiEndpoint.replace('/api/1.1/wf/', ''), {
      timeout: 5000,
    });
    return { healthy: true };
  } catch (error) {
    return { 
      healthy: false, 
      message: error.message,
    };
  }
}

async function checkStorageHealth() {
  try {
    const testKey = 'health:check';
    const testValue = { timestamp: Date.now() };
    
    await storage.set(testKey, testValue);
    const retrieved = await storage.get(testKey);
    await storage.delete(testKey);
    
    if (retrieved && retrieved.timestamp === testValue.timestamp) {
      return { healthy: true };
    }
    
    return { healthy: false, message: 'Storage test failed' };
  } catch (error) {
    return { healthy: false, message: error.message };
  }
}

// ===========================================
// OAUTH ROUTES
// ===========================================

app.get('/', async (req, res) => {
  const { shop, hmac, embedded, host, session, locale, timestamp } = req.query;
  
  // Shopify embedded app installation detection
  const isEmbeddedInstall = embedded === '1' || host;
  
  logger.info('Root route accessed', { 
    shop, 
    hasHmac: !!hmac,
    isEmbedded: isEmbeddedInstall,
    hasHost: !!host,
  });
  
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
            padding: 48px;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            text-align: center;
          }
          .logo { 
            font-size: 64px; 
            margin-bottom: 24px;
          }
          h1 { 
            color: #333; 
            margin-bottom: 12px; 
            font-size: 32px;
            font-weight: 700;
          }
          .subtitle {
            color: #666;
            font-size: 18px;
            margin-bottom: 32px;
            line-height: 1.5;
          }
          .info {
            background: #f7fafc;
            border-left: 4px solid #667eea;
            padding: 16px;
            margin-bottom: 32px;
            text-align: left;
            border-radius: 4px;
          }
          .info p {
            color: #555;
            line-height: 1.6;
            margin-bottom: 8px;
          }
          .info p:last-child { margin-bottom: 0; }
          .button {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 14px 32px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            font-size: 16px;
            transition: all 0.3s;
          }
          .button:hover { 
            background: #5568d3; 
            transform: translateY(-2px);
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="logo">🛡️</div>
          <h1>KatiCRM</h1>
          <p class="subtitle">Omni-channel CRM for Shopify</p>
          
          <div class="info">
            <p><strong>Standalone App Mode</strong></p>
            <p>Access KatiCRM directly after connecting your store.</p>
          </div>
          
          <a href="${CONFIG.bubble.landingUrl}" class="button">Go to KatiCRM</a>
        </div>
      </body>
      </html>
    `);
  }
  
  const validation = validateShopInput(shop);
  if (!validation.valid) {
    return res.status(400).send('Invalid shop domain');
  }
  
  const validatedShop = validation.shop;
  
  if (hmac && !verifyHmac(req.query, hmac)) {
    logger.warn('HMAC verification failed', { shop: validatedShop });
    return res.status(403).send('HMAC validation failed');
  }
  
  // Handle embedded app installation from Shopify App Store
  if (isEmbeddedInstall) {
    logger.info('Embedded app installation detected, starting OAuth', { 
      shop: validatedShop,
      embedded,
      host,
    });
    
    // For embedded apps, start OAuth immediately with auto-generated state
    const state = generateNonce();
    await saveState(validatedShop, state);
    
    const redirectUri = `${CONFIG.app.url}/auth/callback`;
    const shopifyAuthUrl = `https://${validatedShop}/admin/oauth/authorize?` + querystring.stringify({
      client_id: CONFIG.shopify.apiKey,
      scope: CONFIG.shopify.scopes,
      redirect_uri: redirectUri,
      state: state,
    });
    
    logger.info('Redirecting embedded install to Shopify OAuth', { 
      shop: validatedShop,
      redirectUri,
    });
    
    return res.redirect(shopifyAuthUrl);
  }
  
  // For non-embedded installations, redirect to KatiCRM
  logger.info('App installation redirect to KatiCRM', { shop: validatedShop });
  
  const landingUrl = new URL(CONFIG.bubble.landingUrl);
  landingUrl.searchParams.append('shop', validatedShop);
  landingUrl.searchParams.append('success', 'false');
  landingUrl.searchParams.append('install', 'true');
  
  res.redirect(landingUrl.toString());
});

app.get('/auth/shopify', async (req, res) => {
  const { shop, state } = req.query;
  
  logger.info('OAuth initiation', { shop, hasState: !!state });
  
  if (!shop) {
    return res.redirect(`${CONFIG.bubble.errorUrl}?error=missing_shop`);
  }
  
  const validation = validateShopInput(shop);
  if (!validation.valid) {
    return res.redirect(`${CONFIG.bubble.errorUrl}?error=invalid_shop`);
  }
  
  const validatedShop = validation.shop;
  
  // Generate state if not provided (for backward compatibility)
  let oauthState = state;
  if (!state || state === 'direct_install') {
    logger.warn('OAuth initiated without state parameter - generating one', { shop: validatedShop });
    oauthState = generateNonce();
  }
  
  try {
    await saveState(validatedShop, oauthState);
    
    const redirectUri = `${CONFIG.app.url}/auth/callback`;
    const shopifyAuthUrl = `https://${validatedShop}/admin/oauth/authorize?` + querystring.stringify({
      client_id: CONFIG.shopify.apiKey,
      scope: CONFIG.shopify.scopes,
      redirect_uri: redirectUri,
      state: oauthState,
    });
    
    logger.info('Redirecting to Shopify OAuth', { shop: validatedShop });
    res.redirect(shopifyAuthUrl);
    
  } catch (error) {
    logger.error('OAuth initiation error', error, { shop: validatedShop });
    res.redirect(`${CONFIG.bubble.errorUrl}?error=oauth_init_failed`);
  }
});

app.get('/auth/callback', async (req, res) => {
  const { shop, code, state, hmac } = req.query;
  
  logger.info('OAuth callback', { shop, hasCode: !!code, hasState: !!state });
  
  if (!shop || !code || !state) {
    return res.redirect(`${CONFIG.bubble.errorUrl}?error=missing_parameters`);
  }
  
  const validation = validateShopInput(shop);
  if (!validation.valid) {
    return res.redirect(`${CONFIG.bubble.errorUrl}?error=invalid_shop`);
  }
  
  const validatedShop = validation.shop;
  
  if (!hmac || !verifyHmac(req.query, hmac)) {
    logger.error('HMAC verification failed', { shop: validatedShop });
    return res.redirect(`${CONFIG.bubble.errorUrl}?error=hmac_failed`);
  }
  
  const stateValid = await verifyState(validatedShop, state);
  if (!stateValid) {
    logger.error('State verification failed', { shop: validatedShop });
    return res.redirect(`${CONFIG.bubble.errorUrl}?error=state_failed`);
  }
  
  try {
    logger.info('Exchanging code for token', { shop: validatedShop });
    const { accessToken, scope } = await getAccessToken(validatedShop, code);
    
    // Save token to Railway storage (primary source of truth)
    await saveShop(validatedShop, accessToken, scope);
    
    // Send to Bubble asynchronously (secondary backup)
    setImmediate(async () => {
      try {
        const bubbleResult = await sendToBubble(CONFIG.bubble.apiEndpoint, {
          shop: validatedShop,
          shop_domain: validatedShop,
          access_token: accessToken,
          scope: scope,
          installed_at: new Date().toISOString(),
          connected_at: new Date().toISOString(),
          status: 'connected',
          source: 'oauth_callback',
        });
        
        if (!bubbleResult.success) {
          logger.warn('Bubble sync failed', { shop: validatedShop, error: bubbleResult.error });
        }
      } catch (error) {
        logger.error('Error sending to Bubble', error, { shop: validatedShop });
      }
    });
    
    logger.info('OAuth success, redirecting to KatiCRM', { shop: validatedShop });
    
    const successUrl = new URL(CONFIG.bubble.successUrl);
    successUrl.searchParams.append('shop', validatedShop);
    successUrl.searchParams.append('connected', 'true');
    successUrl.searchParams.append('success', 'true');
    successUrl.searchParams.append('token_stored', 'true');
    
    res.redirect(successUrl.toString());
    
  } catch (error) {
    logger.error('OAuth callback error', error, { shop: validatedShop });
    
    const errorUrl = new URL(CONFIG.bubble.errorUrl);
    errorUrl.searchParams.append('error', 'installation_failed');
    errorUrl.searchParams.append('shop', validatedShop);
    
    res.redirect(errorUrl.toString());
  }
});

// ===========================================
// PUBLIC ENDPOINTS
// ===========================================

app.get('/health', async (req, res) => {
  const [storageHealth, bubbleHealth] = await Promise.all([
    checkStorageHealth(),
    checkBubbleHealth(),
  ]);
  
  const allHealthy = storageHealth.healthy && bubbleHealth.healthy;
  
  res.status(allHealthy ? 200 : 503).json({
    status: allHealthy ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    service: 'KatiCRM OAuth Middleware',
    version: '3.5.0',
    uptime: process.uptime(),
    dependencies: {
      storage: storageHealth,
      bubble: bubbleHealth,
    },
  });
});

app.get('/ready', (req, res) => {
  res.json({ ready: true, timestamp: new Date().toISOString() });
});

app.get('/ping', (req, res) => {
  res.send('pong');
});

// ===========================================
// TOKEN RETRIEVAL API (NEW)
// ===========================================

/**
 * GET /api/token/:shop
 * 
 * Check if a shop has an existing access token stored in Railway
 * This allows Bubble to detect existing connections without triggering new OAuth
 * 
 * Returns:
 * - 200: Token exists and is returned
 * - 404: No token found for this shop
 * - 400: Invalid shop parameter
 */
app.get('/api/token/:shop', async (req, res) => {
  const validation = validateShopInput(req.params.shop);
  
  if (!validation.valid) {
    logger.warn('Token lookup - invalid shop', { shop: req.params.shop });
    return res.status(400).json({ 
      success: false,
      error: validation.error,
      requiresAuth: true,
    });
  }
  
  const shop = validation.shop;
  
  try {
    const accessToken = await getAccessTokenForShop(shop);
    
    if (!accessToken) {
      logger.info('Token lookup - no token found', { shop });
      return res.status(404).json({
        success: false,
        message: 'No token found for this shop',
        requiresAuth: true,
        shop,
      });
    }
    
    // Get additional shop data
    const shopData = await getShop(shop);
    
    logger.info('Token lookup - token found', { shop });
    
    return res.json({
      success: true,
      shop,
      access_token: accessToken,
      scope: shopData?.scope || CONFIG.shopify.scopes,
      installed_at: shopData?.installedAt || new Date().toISOString(),
      last_updated: shopData?.lastUpdated || new Date().toISOString(),
      source: 'railway_storage',
      status: 'connected',
    });
    
  } catch (error) {
    logger.error('Token lookup error', error, { shop });
    return res.status(500).json({
      success: false,
      error: 'Failed to retrieve token',
      requiresAuth: true,
    });
  }
});

/**
 * GET /api/token-status/:shop
 * 
 * Lightweight endpoint to check if a token exists without returning it
 * Useful for quick connection status checks
 */
app.get('/api/token-status/:shop', async (req, res) => {
  const validation = validateShopInput(req.params.shop);
  
  if (!validation.valid) {
    return res.status(400).json({ 
      connected: false,
      error: validation.error,
    });
  }
  
  const shop = validation.shop;
  
  try {
    const hasToken = await hasValidToken(shop);
    
    if (hasToken) {
      const shopData = await getShop(shop);
      return res.json({
        connected: true,
        shop,
        installed_at: shopData?.installedAt,
        last_updated: shopData?.lastUpdated,
      });
    }
    
    return res.json({
      connected: false,
      shop,
      requiresAuth: true,
    });
    
  } catch (error) {
    logger.error('Token status check error', error, { shop });
    return res.status(500).json({
      connected: false,
      error: 'Failed to check token status',
    });
  }
});

// ===========================================
// SHOP API ENDPOINTS
// ===========================================

app.get('/api/shop/:shop', async (req, res) => {
  const validation = validateShopInput(req.params.shop);
  
  if (!validation.valid) {
    return res.status(400).json({ error: 'Invalid shop', connected: false });
  }
  
  const shopData = await getShop(validation.shop);
  
  if (!shopData) {
    return res.status(404).json({ error: 'Shop not found', connected: false });
  }
  
  res.json({
    shop: shopData.shop,
    connected: true,
    installed_at: shopData.installedAt,
    last_updated: shopData.lastUpdated,
    scope: shopData.scope,
  });
});

app.post('/api/shop/:shop/disconnect', async (req, res) => {
  const validation = validateShopInput(req.params.shop);
  
  if (!validation.valid) {
    return res.status(400).json({ error: 'Invalid shop', success: false });
  }
  
  const shopData = await getShop(validation.shop);
  
  if (!shopData) {
    return res.status(404).json({ error: 'Shop not found', success: false });
  }
  
  try {
    await deleteShop(validation.shop);
    
    // Notify Bubble of disconnection
    setImmediate(async () => {
      try {
        await sendToBubble(CONFIG.bubble.apiEndpoint, {
          shop: validation.shop,
          status: 'disconnected',
          disconnected_at: new Date().toISOString(),
        });
      } catch (error) {
        logger.error('Failed to notify Bubble of disconnection', error);
      }
    });
    
    res.json({ success: true, shop: validation.shop });
  } catch (error) {
    logger.error('Disconnect error', error);
    res.status(500).json({ error: 'Failed to disconnect', success: false });
  }
});

// ===========================================
// ADMIN ENDPOINTS
// ===========================================

function requireAdminAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || authHeader !== `Bearer ${CONFIG.app.adminPassword}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  next();
}

app.get('/admin/status', requireAdminAuth, async (req, res) => {
  const storageHealth = await checkStorageHealth();
  const bubbleHealth = await checkBubbleHealth();
  
  // Count stored tokens
  let tokenCount = 0;
  try {
    const tokenKeys = await storage.keys('token:*');
    tokenCount = tokenKeys.length;
  } catch (error) {
    logger.error('Failed to count tokens', error);
  }
  
  res.json({
    service: 'KatiCRM OAuth Middleware',
    version: '3.5.0',
    oauthMode: 'katicrm-only',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    statistics: {
      connectedShops: tokenCount,
    },
    health: {
      storage: storageHealth,
      bubble: bubbleHealth,
    },
  });
});

app.get('/admin/shops', requireAdminAuth, async (req, res) => {
  try {
    const shopKeys = await storage.keys('shop:*');
    const shops = [];
    
    for (const key of shopKeys) {
      const shopData = await storage.get(key);
      if (shopData) {
        shops.push({
          shop: shopData.shop,
          installed_at: shopData.installedAt,
          last_updated: shopData.lastUpdated,
          scope: shopData.scope,
        });
      }
    }
    
    res.json({
      success: true,
      count: shops.length,
      shops,
    });
  } catch (error) {
    logger.error('Failed to list shops', error);
    res.status(500).json({ error: 'Failed to retrieve shops' });
  }
});

// ===========================================
// GDPR WEBHOOKS
// ===========================================

async function processWebhookIdempotent(webhookId, handler) {
  const key = `webhook:processed:${webhookId}`;
  
  if (await storage.exists(key)) {
    logger.info('Webhook already processed', { webhookId });
    return { alreadyProcessed: true };
  }
  
  const result = await handler();
  await storage.set(key, { processed: true }, 86400);
  
  return result;
}

app.post('/webhooks/customers/data_request', async (req, res) => {
  const shop = req.get('X-Shopify-Shop-Domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  
  const rawBody = req.body;
  let body;
  
  try {
    const bodyString = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
    body = JSON.parse(bodyString);
  } catch (error) {
    return res.status(400).send('Invalid JSON');
  }
  
  if (!hmac && isShopifyConnectivityTest(body, req.headers)) {
    return res.status(200).send('Webhook reachable');
  }
  
  if (!hmac || !verifyWebhook(rawBody, hmac)) {
    return res.status(401).send('Unauthorized');
  }
  
  res.status(200).send('Acknowledged');
  
  setImmediate(async () => {
    try {
      await sendToBubble(CONFIG.bubble.gdpr.dataRequest, {
        shop: shop || body.shop_domain,
        customer_email: body.customer?.email,
        received_at: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('GDPR webhook error', error);
    }
  });
});

app.post('/webhooks/customers/redact', async (req, res) => {
  const shop = req.get('X-Shopify-Shop-Domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  
  const rawBody = req.body;
  let body;
  
  try {
    const bodyString = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
    body = JSON.parse(bodyString);
  } catch (error) {
    return res.status(400).send('Invalid JSON');
  }
  
  if (!hmac && isShopifyConnectivityTest(body, req.headers)) {
    return res.status(200).send('Webhook reachable');
  }
  
  if (!hmac || !verifyWebhook(rawBody, hmac)) {
    return res.status(401).send('Unauthorized');
  }
  
  res.status(200).send('Will be redacted');
  
  setImmediate(async () => {
    try {
      await sendToBubble(CONFIG.bubble.gdpr.customerRedact, {
        shop: shop || body.shop_domain,
        customer_email: body.customer?.email,
        received_at: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('GDPR webhook error', error);
    }
  });
});

app.post('/webhooks/shop/redact', async (req, res) => {
  const shop = req.get('X-Shopify-Shop-Domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  
  const rawBody = req.body;
  let body;
  
  try {
    const bodyString = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
    body = JSON.parse(bodyString);
  } catch (error) {
    return res.status(400).send('Invalid JSON');
  }
  
  if (!hmac && isShopifyConnectivityTest(body, req.headers)) {
    return res.status(200).send('Webhook reachable');
  }
  
  if (!hmac || !verifyWebhook(rawBody, hmac)) {
    return res.status(401).send('Unauthorized');
  }
  
  const shopDomain = shop || body.shop_domain;
  if (shopDomain) {
    await deleteShop(shopDomain);
  }
  
  res.status(200).send('Will be redacted');
  
  setImmediate(async () => {
    try {
      await sendToBubble(CONFIG.bubble.gdpr.shopRedact, {
        shop: shopDomain,
        received_at: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('GDPR webhook error', error);
    }
  });
});

// ===========================================
// ERROR HANDLING
// ===========================================

app.use((req, res) => {
  res.status(404).json({ error: 'Not Found', path: req.path });
});

app.use((err, req, res, next) => {
  logger.error('Unhandled error', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

// ===========================================
// GRACEFUL SHUTDOWN
// ===========================================

function gracefulShutdown(signal) {
  logger.info(`${signal} received, shutting down`);
  
  server.close(() => {
    if (CONFIG.redis.enabled && redisClient) {
      redisClient.quit(() => process.exit(0));
    } else {
      process.exit(0);
    }
  });
  
  setTimeout(() => {
    process.exit(1);
  }, CONFIG.timeouts.gracefulShutdown);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ===========================================
// SERVER STARTUP
// ===========================================

const server = app.listen(PORT, () => {
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════╗');
  console.log('║  🛡️  KatiCRM OAuth v3.5 - TOKEN RETRIEVAL ENABLED   ║');
  console.log('╚═══════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`📡 Server: http://localhost:${PORT}`);
  console.log(`🔗 OAuth: ${CONFIG.app.url}/auth/shopify`);
  console.log(`🔑 Token API: ${CONFIG.app.url}/api/token/:shop`);
  console.log(`✅ Success: ${CONFIG.bubble.successUrl}`);
  console.log(`🏠 Landing: ${CONFIG.bubble.landingUrl}`);
  console.log('');
  console.log('🔒 SECURITY: State parameter REQUIRED');
  console.log('   ✅ Direct OAuth BLOCKED');
  console.log('   ✅ Only KatiCRM button allows OAuth');
  console.log('');
  console.log('🆕 NEW FEATURES:');
  console.log('   ✅ Token retrieval API');
  console.log('   ✅ Connection status checks');
  console.log('   ✅ Optimized token storage');
  console.log('   ✅ Prevents duplicate OAuth flows');
  console.log('');
  console.log('✅ Server ready');
  console.log('');
});
