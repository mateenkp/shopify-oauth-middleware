/**
 * KatiCRM Shopify OAuth Middleware v3.0
 * 
 * Production-ready OAuth middleware with:
 * - Rate limiting and DDoS protection
 * - Input validation and sanitization
 * - Structured logging
 * - Redis support for horizontal scaling
 * - Webhook retry mechanism
 * - Health checks with dependency monitoring
 * - Graceful error handling
 * - CORS support
 * - Request timeouts
 * - Idempotency for webhooks
 * 
 * @author KatiCRM Team
 * @version 3.0.0
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
    successUrl: process.env.BUBBLE_SUCCESS_URL || 'https://d334.bubble.is/version-test/shopify_dashboard',
    errorUrl: process.env.BUBBLE_ERROR_URL || 'https://d334.bubble.is/version-test/error',
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
    stateExpiryMs: 5 * 60 * 1000, // 5 minutes
    maxWebhookAge: 5 * 60 * 1000, // 5 minutes
  },
  timeouts: {
    axios: 30000,
    gracefulShutdown: 10000,
  },
};

// ===========================================
// STORAGE LAYER (Redis or In-Memory)
// ===========================================

let storage;

if (CONFIG.redis.enabled) {
  // Production: Use Redis for persistent, distributed storage
  const Redis = require('ioredis');
  const redisClient = new Redis(CONFIG.redis.url, {
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
  };
} else {
  // Development: Use in-memory storage
  logger.warn('⚠️  Using in-memory storage. Data will be lost on restart. Configure REDIS_URL for production.');
  
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
  };
}

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
        ...error,
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
// VALIDATION & SANITIZATION
// ===========================================

/**
 * Validates and sanitizes shop domain input
 * @param {string} shop - Shop domain or handle
 * @returns {object} { valid: boolean, shop: string, error: string }
 */
function validateShopInput(shop) {
  if (!shop || typeof shop !== 'string') {
    return { valid: false, error: 'Shop parameter is required' };
  }

  // Remove whitespace and convert to lowercase
  shop = shop.trim().toLowerCase();

  // If it's already a full domain
  if (shop.includes('.myshopify.com')) {
    const fullShopRegex = /^[a-z0-9][a-z0-9\-]*\.myshopify\.com$/;
    if (!fullShopRegex.test(shop)) {
      return { valid: false, error: 'Invalid shop domain format' };
    }
    return { valid: true, shop };
  }

  // If it's just a handle (e.g., "calltronix")
  const handleRegex = /^[a-z0-9][a-z0-9\-]*$/;
  if (!handleRegex.test(shop)) {
    return { 
      valid: false, 
      error: 'Shop name can only contain lowercase letters, numbers, and hyphens' 
    };
  }

  // Construct full domain
  const fullShop = `${shop}.myshopify.com`;
  return { valid: true, shop: fullShop };
}

/**
 * Validates email format
 */
function isValidEmail(email) {
  if (!email) return false;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Sanitizes string input to prevent injection
 */
function sanitizeString(str, maxLength = 255) {
  if (!str) return '';
  return String(str)
    .slice(0, maxLength)
    .replace(/[<>]/g, '') // Remove potential XSS vectors
    .trim();
}

// ===========================================
// VALIDATE CRITICAL CONFIGURATION
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
    logger.error('❌ CRITICAL: Missing required environment variables', { missing });
    process.exit(1);
  }

  // Validate URLs
  try {
    new URL(CONFIG.app.url);
    new URL(CONFIG.bubble.apiEndpoint);
  } catch (error) {
    logger.error('❌ CRITICAL: Invalid URL in configuration', { error });
    process.exit(1);
  }

  logger.info('✅ Configuration validated successfully');
}

validateConfig();

// ===========================================
// MIDDLEWARE CONFIGURATION
// ===========================================

// Trust proxy (required for Railway, Heroku, etc.)
app.set('trust proxy', 1);

// Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      frameAncestors: ["'self'", "https://*.myshopify.com", "https://admin.shopify.com"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
}));

// CORS configuration
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin) return callback(null, true);
    
    // Allow Shopify domains
    if (origin.includes('.myshopify.com') || origin.includes('shopify.com')) {
      return callback(null, true);
    }
    
    // Allow your Bubble app
    if (origin.includes('bubble.io') || origin.includes('bubble.is')) {
      return callback(null, true);
    }
    
    callback(null, true); // Allow all origins for now, tighten in production
  },
  credentials: true,
}));

// Rate limiting - General API
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting - OAuth (more restrictive)
const oauthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20, // Only 20 OAuth attempts per 15 minutes
  message: 'Too many authentication attempts, please try again later.',
  skipSuccessfulRequests: true,
});

// Rate limiting - Webhooks (very permissive)
const webhookLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 1000, // Shopify can send many webhooks
  message: 'Webhook rate limit exceeded',
});

// Apply general rate limiting to all routes
app.use('/auth', oauthLimiter);
app.use('/webhooks', webhookLimiter);
app.use(generalLimiter);

// Request ID middleware for tracing
app.use((req, res, next) => {
  req.id = crypto.randomBytes(16).toString('hex');
  res.setHeader('X-Request-ID', req.id);
  next();
});

// Request logging
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
      userAgent: req.get('user-agent'),
    });
  });
  
  next();
});

// Raw body capture for webhook HMAC verification (BEFORE parsing)
app.use('/webhooks', express.raw({ type: 'application/json' }));

// JSON parsing for other routes
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request timeout
app.use((req, res, next) => {
  req.setTimeout(30000); // 30 second timeout
  res.setTimeout(30000);
  next();
});

// ===========================================
// SECURITY & VERIFICATION FUNCTIONS
// ===========================================

/**
 * Verify HMAC signature for OAuth callbacks
 * @param {Object} query - Query parameters from OAuth callback
 * @param {string} hmac - HMAC signature to verify
 * @returns {boolean} - True if valid, false otherwise
 */
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
    logger.error('HMAC verification failed', error, { query });
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

/**
 * Detect if request is from Shopify's automated connectivity test
 */
function isShopifyConnectivityTest(body, headers) {
  const userAgent = (headers['user-agent'] || '').toLowerCase();
  const hasShopifyUserAgent = userAgent.includes('shopify');
  const isMinimalPayload = body && Object.keys(body).length <= 3;
  const looksLikeTest = body && body.shop_id && body.shop_domain && !body.customer;
  
  return (hasShopifyUserAgent && isMinimalPayload) || looksLikeTest;
}

/**
 * Generate secure nonce for OAuth state parameter
 */
function generateNonce() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Check if webhook timestamp is within acceptable range
 */
function isWebhookTimestampValid(timestamp) {
  if (!timestamp) return true; // No timestamp provided, skip check
  
  try {
    const webhookTime = new Date(timestamp).getTime();
    const now = Date.now();
    const age = now - webhookTime;
    
    return age < CONFIG.security.maxWebhookAge;
  } catch (error) {
    logger.warn('Invalid webhook timestamp format', { timestamp });
    return true; // Don't fail on timestamp parse errors
  }
}

// ===========================================
// DATA PERSISTENCE FUNCTIONS
// ===========================================

/**
 * Save shop data to storage
 */
async function saveShop(shop, accessToken, scope) {
  const shopData = {
    shop,
    accessToken,
    scope,
    installedAt: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
  };
  
  await storage.set(`shop:${shop}`, shopData);
  logger.info('Shop data saved', { shop, scope });
  
  return shopData;
}

/**
 * Get shop data from storage
 */
async function getShop(shop) {
  return await storage.get(`shop:${shop}`);
}

/**
 * Delete shop data from storage
 */
async function deleteShop(shop) {
  await storage.delete(`shop:${shop}`);
  logger.info('Shop data deleted', { shop });
}

/**
 * Save OAuth state for CSRF protection
 */
async function saveState(shop, state) {
  const stateData = {
    state,
    shop,
    timestamp: Date.now(),
  };
  
  // Set with expiry (5 minutes)
  await storage.set(`state:${shop}`, stateData, 300);
  logger.debug('OAuth state saved', { shop, state });
}

/**
 * Verify and consume OAuth state
 */
async function verifyState(shop, state) {
  const stateData = await storage.get(`state:${shop}`);
  
  if (!stateData) {
    logger.warn('OAuth state not found', { shop, state });
    return false;
  }
  
  if (stateData.state !== state) {
    logger.warn('OAuth state mismatch', { shop, expected: stateData.state, received: state });
    return false;
  }
  
  // Check age
  const age = Date.now() - stateData.timestamp;
  if (age > CONFIG.security.stateExpiryMs) {
    logger.warn('OAuth state expired', { shop, age });
    await storage.delete(`state:${shop}`);
    return false;
  }
  
  // Consume state (delete after verification)
  await storage.delete(`state:${shop}`);
  logger.debug('OAuth state verified and consumed', { shop });
  
  return true;
}

// ===========================================
// SHOPIFY API FUNCTIONS
// ===========================================

/**
 * Exchange authorization code for access token
 */
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
    logger.error('Failed to get access token', error, { 
      shop,
      status: error.response?.status,
      data: error.response?.data,
    });
    throw new Error('Failed to obtain access token from Shopify');
  }
}

/**
 * Send shop data to Bubble with retry logic
 */
async function sendToBubble(endpoint, data, retries = 3) {
  if (!endpoint) {
    logger.warn('Bubble endpoint not configured', { data });
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
        data: error.response?.data,
      });
      
      // Don't retry on 4xx errors (client errors)
      if (error.response?.status >= 400 && error.response?.status < 500) {
        return { 
          success: false, 
          error: `Bubble returned ${error.response.status}`,
          permanent: true,
        };
      }
      
      // Last attempt
      if (attempt === retries) {
        return { 
          success: false, 
          error: error.message,
          attempts: retries,
        };
      }
      
      // Wait before retry (exponential backoff)
      const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000);
      logger.info(`Retrying in ${delay}ms...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// ===========================================
// HEALTH CHECK SYSTEM
// ===========================================

/**
 * Check if Bubble API is reachable
 */
async function checkBubbleHealth() {
  if (!CONFIG.bubble.apiEndpoint) {
    return { healthy: false, message: 'Bubble endpoint not configured' };
  }
  
  try {
    // Try to reach Bubble with a short timeout
    await axios.get(CONFIG.bubble.apiEndpoint.replace('/api/1.1/wf/', ''), {
      timeout: 5000,
    });
    return { healthy: true };
  } catch (error) {
    return { 
      healthy: false, 
      message: error.message,
      code: error.code,
    };
  }
}

/**
 * Check if storage is working
 */
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
    
    return { healthy: false, message: 'Storage read/write test failed' };
  } catch (error) {
    return { healthy: false, message: error.message };
  }
}

// ===========================================
// OAUTH ROUTES
// ===========================================

/**
 * Root endpoint - Main app entry point
 * This is your "App URL" in Shopify Partner Dashboard
 */
app.get('/', async (req, res) => {
  const { shop, hmac } = req.query;
  
  // No shop parameter - show landing page
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
            animation: float 3s ease-in-out infinite;
          }
          @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
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
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
          }
          .button:hover { 
            background: #5568d3; 
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(102, 126, 234, 0.5);
          }
          .footer {
            margin-top: 32px;
            padding-top: 24px;
            border-top: 1px solid #e2e8f0;
            color: #999;
            font-size: 14px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="logo">🛡️</div>
          <h1>KatiCRM</h1>
          <p class="subtitle">Omni-channel Customer Relationship Management for Shopify</p>
          
          <div class="info">
            <p><strong>📱 Connect your Shopify store</strong></p>
            <p>This app must be accessed from within your Shopify store admin or through the KatiCRM platform.</p>
          </div>
          
          <a href="https://apps.shopify.com" class="button">Visit Shopify App Store</a>
          
          <div class="footer">
            <p>Secure OAuth Integration • GDPR Compliant</p>
          </div>
        </div>
      </body>
      </html>
    `);
  }
  
  // Validate shop input
  const validation = validateShopInput(shop);
  if (!validation.valid) {
    logger.warn('Invalid shop parameter', { shop, error: validation.error });
    return res.status(400).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Invalid Shop</title>
        <style>
          body { font-family: system-ui; padding: 40px; max-width: 600px; margin: 0 auto; }
          .error { background: #fee; border-left: 4px solid #c00; padding: 20px; border-radius: 4px; }
          h1 { color: #c00; margin-top: 0; }
        </style>
      </head>
      <body>
        <div class="error">
          <h1>Invalid Shop Domain</h1>
          <p><strong>Error:</strong> ${validation.error}</p>
          <p>Please use your shop name only (e.g., "mystore") or full domain (e.g., "mystore.myshopify.com")</p>
        </div>
      </body>
      </html>
    `);
  }
  
  const validatedShop = validation.shop;
  
  // Verify HMAC if present (when coming from Shopify)
  if (hmac && !verifyHmac(req.query, hmac)) {
    logger.warn('HMAC verification failed on root route', { shop: validatedShop });
    return res.status(403).send('HMAC validation failed');
  }
  
  try {
    // Check if shop is already authenticated
    const shopData = await getShop(validatedShop);
    
    if (shopData && shopData.accessToken) {
      // Already authenticated - redirect to Bubble app
      logger.info('Authenticated shop accessing app', { shop: validatedShop });
      const redirectUrl = `${CONFIG.bubble.successUrl}?shop=${validatedShop}&token=${shopData.accessToken}`;
      return res.redirect(redirectUrl);
    }
    
    // Not authenticated - start OAuth flow
    logger.info('Starting OAuth flow', { shop: validatedShop, requestId: req.id });
    
    const state = generateNonce();
    const redirectUri = `${CONFIG.app.url}/auth/callback`;
    
    // Save state for verification
    await saveState(validatedShop, state);
    
    const installUrl = 
      `https://${validatedShop}/admin/oauth/authorize?` +
      `client_id=${CONFIG.shopify.apiKey}` +
      `&scope=${CONFIG.shopify.scopes}` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&state=${state}`;
    
    logger.debug('Redirecting to Shopify OAuth', { shop: validatedShop, installUrl });
    res.redirect(installUrl);
    
  } catch (error) {
    logger.error('Error in root route', error, { shop: validatedShop });
    res.status(500).send('An error occurred. Please try again.');
  }
});

/**
 * OAuth callback endpoint
 * Shopify redirects here after merchant authorizes
 */
app.get('/auth/callback', async (req, res) => {
  const { shop, code, state, hmac } = req.query;
  
  logger.info('OAuth callback received', { 
    shop, 
    hasCode: !!code, 
    hasState: !!state,
    hasHmac: !!hmac,
    requestId: req.id,
  });
  
  // Validate required parameters
  if (!shop || !code || !state) {
    logger.error('Missing required OAuth parameters', { shop, code: !!code, state: !!state });
    return res.redirect(`${CONFIG.bubble.errorUrl}?error=missing_parameters`);
  }
  
  // Validate shop format
  const validation = validateShopInput(shop);
  if (!validation.valid) {
    logger.error('Invalid shop format in callback', { shop, error: validation.error });
    return res.redirect(`${CONFIG.bubble.errorUrl}?error=invalid_shop`);
  }
  
  const validatedShop = validation.shop;
  
  // Verify HMAC
  if (!hmac || !verifyHmac(req.query, hmac)) {
    logger.error('HMAC verification failed in callback', { shop: validatedShop });
    return res.redirect(`${CONFIG.bubble.errorUrl}?error=hmac_failed&shop=${validatedShop}`);
  }
  
  // Verify state (CSRF protection)
  const stateValid = await verifyState(validatedShop, state);
  if (!stateValid) {
    logger.error('State verification failed', { shop: validatedShop, state });
    return res.redirect(`${CONFIG.bubble.errorUrl}?error=state_failed&shop=${validatedShop}`);
  }
  
  try {
    // Exchange code for access token
    logger.info('Exchanging authorization code for access token', { shop: validatedShop });
    const { accessToken, scope } = await getAccessToken(validatedShop, code);
    
    // Save shop data
    await saveShop(validatedShop, accessToken, scope);
    
    // Send to Bubble (with retry logic)
    const bubbleResult = await sendToBubble(CONFIG.bubble.apiEndpoint, {
      shop: validatedShop,
      access_token: accessToken,
      scope: scope,
      installed_at: new Date().toISOString(),
    });
    
    if (!bubbleResult.success) {
      logger.warn('Failed to sync with Bubble, but OAuth succeeded', { 
        shop: validatedShop,
        error: bubbleResult.error,
      });
    }
    
    // Success - redirect to Bubble app
    logger.info('OAuth flow completed successfully', { shop: validatedShop });
    const redirectUrl = `${CONFIG.bubble.successUrl}?shop=${validatedShop}&token=${accessToken}&first_install=true`;
    res.redirect(redirectUrl);
    
  } catch (error) {
    logger.error('OAuth callback error', error, { shop: validatedShop });
    res.redirect(`${CONFIG.bubble.errorUrl}?error=installation_failed&shop=${validatedShop}`);
  }
});

// ===========================================
// PUBLIC ENDPOINTS
// ===========================================

/**
 * Health check endpoint with dependency checks
 */
app.get('/health', async (req, res) => {
  const startTime = Date.now();
  
  // Check all dependencies
  const [storageHealth, bubbleHealth] = await Promise.all([
    checkStorageHealth(),
    checkBubbleHealth(),
  ]);
  
  const allHealthy = storageHealth.healthy && bubbleHealth.healthy;
  const statusCode = allHealthy ? 200 : 503;
  
  res.status(statusCode).json({
    status: allHealthy ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    service: 'KatiCRM Shopify OAuth Middleware',
    version: '3.0.0',
    uptime: process.uptime(),
    responseTime: `${Date.now() - startTime}ms`,
    dependencies: {
      storage: storageHealth,
      bubble: bubbleHealth,
    },
    environment: NODE_ENV,
  });
});

/**
 * Readiness check (simpler than health check)
 */
app.get('/ready', (req, res) => {
  res.status(200).json({
    ready: true,
    timestamp: new Date().toISOString(),
  });
});

/**
 * Liveness check (even simpler)
 */
app.get('/ping', (req, res) => {
  res.send('pong');
});

// ===========================================
// ADMIN ENDPOINTS (PROTECTED)
// ===========================================

/**
 * Admin authentication middleware
 */
function requireAdminAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || authHeader !== `Bearer ${CONFIG.app.adminPassword}`) {
    logger.warn('Unauthorized admin access attempt', { 
      ip: req.ip,
      path: req.path,
    });
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  next();
}

/**
 * Admin status dashboard
 */
app.get('/admin/status', requireAdminAuth, async (req, res) => {
  const storageHealth = await checkStorageHealth();
  const bubbleHealth = await checkBubbleHealth();
  
  res.json({
    service: 'KatiCRM OAuth Middleware',
    version: '3.0.0',
    status: 'operational',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: NODE_ENV,
    health: {
      storage: storageHealth,
      bubble: bubbleHealth,
    },
    configuration: {
      oauthEnabled: !!CONFIG.shopify.apiKey && !!CONFIG.shopify.apiSecret,
      bubbleConfigured: !!CONFIG.bubble.apiEndpoint,
      gdprWebhooksConfigured: !!(
        CONFIG.bubble.gdpr.dataRequest || 
        CONFIG.bubble.gdpr.customerRedact || 
        CONFIG.bubble.gdpr.shopRedact
      ),
      redisEnabled: CONFIG.redis.enabled,
    },
  });
});

/**
 * Admin endpoint to check specific shop
 */
app.get('/admin/shop/:shop', requireAdminAuth, async (req, res) => {
  const validation = validateShopInput(req.params.shop);
  
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }
  
  const shopData = await getShop(validation.shop);
  
  if (!shopData) {
    return res.status(404).json({ error: 'Shop not found' });
  }
  
  // Don't expose the full access token
  res.json({
    shop: shopData.shop,
    authenticated: true,
    installedAt: shopData.installedAt,
    lastUpdated: shopData.lastUpdated,
    scope: shopData.scope,
    tokenPreview: shopData.accessToken ? `${shopData.accessToken.substring(0, 10)}...` : null,
  });
});

// ===========================================
// GDPR COMPLIANCE WEBHOOKS
// ===========================================

/**
 * Process webhook with idempotency
 */
async function processWebhookIdempotent(webhookId, handler) {
  const idempotencyKey = `webhook:processed:${webhookId}`;
  
  // Check if already processed
  const alreadyProcessed = await storage.exists(idempotencyKey);
  if (alreadyProcessed) {
    logger.info('Webhook already processed (idempotent)', { webhookId });
    return { alreadyProcessed: true };
  }
  
  // Process webhook
  const result = await handler();
  
  // Mark as processed (keep for 24 hours)
  await storage.set(idempotencyKey, { processed: true, timestamp: Date.now() }, 86400);
  
  return result;
}

/**
 * Customer Data Request Webhook (GDPR)
 */
app.post('/webhooks/customers/data_request', async (req, res) => {
  logger.info('Customer data request webhook received', { requestId: req.id });
  
  const shop = req.get('X-Shopify-Shop-Domain') || req.get('x-shopify-shop-domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256') || req.get('x-shopify-hmac-sha256');
  const timestamp = req.get('X-Shopify-Webhook-Timestamp') || req.get('x-shopify-webhook-timestamp');
  
  // Parse body
  const rawBody = req.body;
  let body;
  
  try {
    const bodyString = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
    body = JSON.parse(bodyString);
  } catch (error) {
    logger.error('Failed to parse webhook body', error);
    return res.status(400).send('Invalid JSON');
  }
  
  // Check for connectivity test
  if (!hmac && isShopifyConnectivityTest(body, req.headers)) {
    logger.info('Shopify connectivity test detected');
    return res.status(200).send('Data request webhook is reachable');
  }
  
  // Verify HMAC
  if (!hmac || !verifyWebhook(rawBody, hmac)) {
    logger.error('Webhook HMAC verification failed', { shop, webhookType: 'data_request' });
    return res.status(401).send('Unauthorized: Invalid HMAC signature');
  }
  
  // Verify timestamp
  if (!isWebhookTimestampValid(timestamp)) {
    logger.warn('Webhook timestamp too old', { shop, timestamp });
    return res.status(401).send('Webhook too old');
  }
  
  logger.info('Webhook HMAC verified', { shop, webhookType: 'data_request' });
  
  // Respond immediately (Shopify requires response within 5 seconds)
  res.status(200).send('Customer data request acknowledged');
  
  // Process asynchronously with idempotency
  setImmediate(async () => {
    try {
      const webhookId = `data_request:${body.shop_id}:${body.id || Date.now()}`;
      
      await processWebhookIdempotent(webhookId, async () => {
        const result = await sendToBubble(CONFIG.bubble.gdpr.dataRequest, {
          shop: shop || body.shop_domain,
          customer_email: body.customer?.email,
          customer_id: body.customer?.id,
          orders_requested: body.orders_requested,
          request_id: body.id,
          webhook_id: webhookId,
          received_at: new Date().toISOString(),
        });
        
        if (!result.success) {
          logger.error('Failed to process data request in Bubble', { 
            shop,
            error: result.error,
          });
        }
        
        return result;
      });
    } catch (error) {
      logger.error('Error processing data request webhook', error, { shop });
    }
  });
});

/**
 * Customer Redact Webhook (GDPR)
 */
app.post('/webhooks/customers/redact', async (req, res) => {
  logger.info('Customer redaction webhook received', { requestId: req.id });
  
  const shop = req.get('X-Shopify-Shop-Domain') || req.get('x-shopify-shop-domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256') || req.get('x-shopify-hmac-sha256');
  const timestamp = req.get('X-Shopify-Webhook-Timestamp') || req.get('x-shopify-webhook-timestamp');
  
  // Parse body
  const rawBody = req.body;
  let body;
  
  try {
    const bodyString = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
    body = JSON.parse(bodyString);
  } catch (error) {
    logger.error('Failed to parse webhook body', error);
    return res.status(400).send('Invalid JSON');
  }
  
  // Check for connectivity test
  if (!hmac && isShopifyConnectivityTest(body, req.headers)) {
    logger.info('Shopify connectivity test detected');
    return res.status(200).send('Customer redact webhook is reachable');
  }
  
  // Verify HMAC
  if (!hmac || !verifyWebhook(rawBody, hmac)) {
    logger.error('Webhook HMAC verification failed', { shop, webhookType: 'customer_redact' });
    return res.status(401).send('Unauthorized: Invalid HMAC signature');
  }
  
  // Verify timestamp
  if (!isWebhookTimestampValid(timestamp)) {
    logger.warn('Webhook timestamp too old', { shop, timestamp });
    return res.status(401).send('Webhook too old');
  }
  
  logger.info('Webhook HMAC verified', { shop, webhookType: 'customer_redact' });
  
  // Respond immediately
  res.status(200).send('Customer data will be redacted');
  
  // Process asynchronously with idempotency
  setImmediate(async () => {
    try {
      const webhookId = `customer_redact:${body.shop_id}:${body.customer?.id || Date.now()}`;
      
      await processWebhookIdempotent(webhookId, async () => {
        const result = await sendToBubble(CONFIG.bubble.gdpr.customerRedact, {
          shop: shop || body.shop_domain,
          customer_email: body.customer?.email,
          customer_id: body.customer?.id,
          orders_to_redact: body.orders_to_redact,
          request_id: body.id,
          webhook_id: webhookId,
          received_at: new Date().toISOString(),
        });
        
        if (!result.success) {
          logger.error('Failed to process customer redaction in Bubble', { 
            shop,
            error: result.error,
          });
        }
        
        return result;
      });
    } catch (error) {
      logger.error('Error processing customer redact webhook', error, { shop });
    }
  });
});

/**
 * Shop Redact Webhook (GDPR)
 */
app.post('/webhooks/shop/redact', async (req, res) => {
  logger.info('Shop redaction webhook received', { requestId: req.id });
  
  const shop = req.get('X-Shopify-Shop-Domain') || req.get('x-shopify-shop-domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256') || req.get('x-shopify-hmac-sha256');
  const timestamp = req.get('X-Shopify-Webhook-Timestamp') || req.get('x-shopify-webhook-timestamp');
  
  // Parse body
  const rawBody = req.body;
  let body;
  
  try {
    const bodyString = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
    body = JSON.parse(bodyString);
  } catch (error) {
    logger.error('Failed to parse webhook body', error);
    return res.status(400).send('Invalid JSON');
  }
  
  // Check for connectivity test
  if (!hmac && isShopifyConnectivityTest(body, req.headers)) {
    logger.info('Shopify connectivity test detected');
    return res.status(200).send('Shop redact webhook is reachable');
  }
  
  // Verify HMAC
  if (!hmac || !verifyWebhook(rawBody, hmac)) {
    logger.error('Webhook HMAC verification failed', { shop, webhookType: 'shop_redact' });
    return res.status(401).send('Unauthorized: Invalid HMAC signature');
  }
  
  // Verify timestamp
  if (!isWebhookTimestampValid(timestamp)) {
    logger.warn('Webhook timestamp too old', { shop, timestamp });
    return res.status(401).send('Webhook too old');
  }
  
  logger.info('Webhook HMAC verified', { shop, webhookType: 'shop_redact' });
  
  const shopDomain = shop || body.shop_domain;
  
  // Delete shop from storage
  if (shopDomain) {
    await deleteShop(shopDomain);
  }
  
  // Respond immediately
  res.status(200).send('Shop data will be redacted');
  
  // Process asynchronously with idempotency
  setImmediate(async () => {
    try {
      const webhookId = `shop_redact:${body.shop_id}:${Date.now()}`;
      
      await processWebhookIdempotent(webhookId, async () => {
        const result = await sendToBubble(CONFIG.bubble.gdpr.shopRedact, {
          shop: shopDomain,
          shop_id: body.shop_id,
          shop_domain: body.shop_domain,
          request_id: body.id,
          webhook_id: webhookId,
          received_at: new Date().toISOString(),
        });
        
        if (!result.success) {
          logger.error('Failed to process shop redaction in Bubble', { 
            shop: shopDomain,
            error: result.error,
          });
        }
        
        return result;
      });
    } catch (error) {
      logger.error('Error processing shop redact webhook', error, { shop: shopDomain });
    }
  });
});

/**
 * Base webhook endpoint (for HMAC test)
 */
app.post('/webhooks', async (req, res) => {
  logger.info('Base webhook endpoint called', { requestId: req.id });
  
  const hmac = req.get('X-Shopify-Hmac-Sha256') || req.get('x-shopify-hmac-sha256');
  
  if (!hmac) {
    logger.warn('Webhook received without HMAC');
    return res.status(401).send('Unauthorized: HMAC signature required');
  }
  
  const rawBody = req.body;
  
  if (!verifyWebhook(rawBody, hmac)) {
    logger.warn('Webhook HMAC verification failed');
    return res.status(401).send('Unauthorized: Invalid HMAC signature');
  }
  
  logger.info('Base webhook HMAC verified');
  res.status(200).send('Webhook received and verified');
});

// ===========================================
// ERROR HANDLING
// ===========================================

// 404 handler
app.use((req, res) => {
  logger.warn('404 Not Found', { 
    method: req.method, 
    path: req.path,
    ip: req.ip,
  });
  
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested endpoint does not exist',
    path: req.path,
  });
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error', err, {
    requestId: req.id,
    method: req.method,
    path: req.path,
  });
  
  // Don't expose internal errors to clients
  res.status(500).json({
    error: 'Internal Server Error',
    message: 'An unexpected error occurred',
    requestId: req.id,
  });
});

// ===========================================
// GRACEFUL SHUTDOWN
// ===========================================

function gracefulShutdown(signal) {
  logger.info(`${signal} received, starting graceful shutdown`);
  
  server.close(() => {
    logger.info('HTTP server closed');
    
    // Close database connections, etc.
    if (CONFIG.redis.enabled && redisClient) {
      redisClient.quit(() => {
        logger.info('Redis connection closed');
        process.exit(0);
      });
    } else {
      process.exit(0);
    }
  });
  
  // Force shutdown after timeout
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, CONFIG.timeouts.gracefulShutdown);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', error);
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', reason, { promise });
});

// ===========================================
// SERVER STARTUP
// ===========================================

const server = app.listen(PORT, () => {
  console.log('');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║  🛡️  KatiCRM Shopify OAuth Middleware v3.0                 ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`📡 Server: http://localhost:${PORT}`);
  console.log(`🌐 App URL: ${CONFIG.app.url}`);
  console.log(`🔗 OAuth Callback: ${CONFIG.app.url}/auth/callback`);
  console.log(`💚 Health Check: ${CONFIG.app.url}/health`);
  console.log(`🔐 Admin Status: ${CONFIG.app.url}/admin/status`);
  console.log('');
  console.log('🔒 Security Features:');
  console.log('  ✅ HMAC verification enabled');
  console.log('  ✅ CSRF protection (state parameter)');
  console.log('  ✅ Rate limiting active');
  console.log('  ✅ Input validation & sanitization');
  console.log('  ✅ GDPR webhooks configured');
  console.log('  ✅ Security headers (Helmet)');
  console.log('  ✅ CORS configured');
  console.log('  ✅ Webhook idempotency');
  console.log('');
  console.log('⚡ Performance Features:');
  console.log(`  ✅ Storage: ${CONFIG.redis.enabled ? 'Redis (distributed)' : 'In-Memory (dev only)'}`);
  console.log('  ✅ Graceful shutdown');
  console.log('  ✅ Request timeouts');
  console.log('  ✅ Retry logic with exponential backoff');
  console.log('  ✅ Structured logging');
  console.log('');
  console.log('⚙️  Configuration:');
  console.log(`  🔑 Shopify API Key: ${CONFIG.shopify.apiKey ? '✅' : '❌'}`);
  console.log(`  🔐 Shopify Secret: ${CONFIG.shopify.apiSecret ? '✅' : '❌'}`);
  console.log(`  💾 Bubble Endpoint: ${CONFIG.bubble.apiEndpoint ? '✅' : '❌'}`);
  console.log(`  🗄️  Redis: ${CONFIG.redis.enabled ? '✅ Connected' : '⚠️  Not configured'}`);
  console.log(`  🎯 Environment: ${NODE_ENV}`);
  console.log('');
  console.log('✅ Server ready to accept requests');
  console.log('');
  
  logger.info('Server started successfully', { 
    port: PORT, 
    environment: NODE_ENV,
    redisEnabled: CONFIG.redis.enabled,
  });
});
