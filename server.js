/**
 * KatiCRM Shopify Middleware v4.0 — Session Token + Token Exchange Architecture
 *
 * AUTH FLOW (Embedded App / App Bridge):
 * 1. React app calls App Bridge getSessionToken() → JWT signed with API secret
 * 2. React app sends JWT to POST /api/shopify/auth
 * 3. Backend verifies JWT, exchanges for offline access token via Shopify Token Exchange API
 * 4. Access token stored in Redis/memory; Bubble.io notified in background
 * 5. Webhooks registered automatically after first token exchange
 *
 * 2-WAY SYNC:
 * Shopify → Bubble: webhooks (orders, customers, products) forwarded to BUBBLE_API_ENDPOINT
 * Bubble → Shopify: POST /api/shopify/graphql proxies queries & mutations
 *
 * @author KatiCRM Team
 * @version 4.0.0
 */

'use strict';

const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const jwt = require('jsonwebtoken');
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
    apiVersion: '2024-01',
  },
  bubble: {
    apiEndpoint: process.env.BUBBLE_API_ENDPOINT,
    wfBaseUrl: process.env.BUBBLE_WF_BASE_URL,
    gdpr: {
      dataRequest: process.env.BUBBLE_GDPR_DATA_REQUEST,
      customerRedact: process.env.BUBBLE_GDPR_CUSTOMER_REDACT,
      shopRedact: process.env.BUBBLE_GDPR_SHOP_REDACT,
    },
  },
  webhookBaseUrl: process.env.WEBHOOK_BASE_URL,
  redis: {
    enabled: !!process.env.REDIS_URL,
    url: process.env.REDIS_URL,
  },
  security: {
    maxWebhookAge: 5 * 60 * 1000,
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
// VALIDATE CONFIGURATION
// ===========================================

function validateConfig() {
  const required = {
    'SHOPIFY_API_KEY': CONFIG.shopify.apiKey,
    'SHOPIFY_API_SECRET': CONFIG.shopify.apiSecret,
  };

  const missing = Object.entries(required)
    .filter(([, value]) => !value)
    .map(([key]) => key);

  if (missing.length > 0) {
    logger.error('❌ Missing required environment variables', { missing });
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
      frameAncestors: ["'self'", '*.myshopify.com', 'https://admin.shopify.com'],
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
    if (
      origin.includes('.myshopify.com') ||
      origin.includes('shopify.com') ||
      origin.includes('bubble.io') ||
      origin.includes('bubble.is') ||
      origin.includes('katicrm.com')
    ) {
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

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
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

app.use('/api', authLimiter);
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

// IMPORTANT: raw body for webhooks (HMAC requires raw bytes) MUST come before express.json()
app.use('/webhooks', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  req.setTimeout(30000);
  res.setTimeout(30000);
  next();
});

// ===========================================
// WEBHOOK BODY HELPER
// ===========================================

function parseWebhookBody(rawBody) {
  try {
    return {
      ok: true,
      body: JSON.parse(Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : String(rawBody)),
    };
  } catch {
    return { ok: false };
  }
}

// ===========================================
// WEBHOOK HMAC VERIFICATION
// ===========================================

function verifyWebhook(rawBody, hmac) {
  if (!hmac || !CONFIG.shopify.apiSecret) {
    return false;
  }

  try {
    const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody), 'utf8');

    const calculatedHmac = crypto
      .createHmac('sha256', CONFIG.shopify.apiSecret)
      .update(body)
      .digest('base64');

    // Compare base64 strings as UTF-8 bytes; trim header value to handle
    // any trailing whitespace that HTTP proxies may inject
    const providedHmac = hmac.trim();
    if (calculatedHmac.length !== providedHmac.length) {
      return false;
    }
    return crypto.timingSafeEqual(
      Buffer.from(calculatedHmac, 'utf8'),
      Buffer.from(providedHmac, 'utf8')
    );
  } catch (error) {
    logger.error('Webhook HMAC verification failed', error);
    return false;
  }
}

function isWebhookTimestampValid(timestamp) {
  if (!timestamp) return true;
  try {
    const age = Date.now() - new Date(timestamp).getTime();
    return age < CONFIG.security.maxWebhookAge;
  } catch {
    return true;
  }
}

// ===========================================
// SESSION TOKEN VERIFICATION
// ===========================================

function verifySessionToken(token) {
  if (!token) return { valid: false, error: 'No token provided' };

  try {
    const payload = jwt.verify(token, CONFIG.shopify.apiSecret, {
      algorithms: ['HS256'],
      audience: CONFIG.shopify.apiKey,
    });

    if (!payload.dest) return { valid: false, error: 'Missing dest claim' };

    const shopHost = new URL(payload.dest).hostname;
    if (!shopHost.endsWith('.myshopify.com')) {
      return { valid: false, error: 'Invalid shop domain' };
    }

    if (!payload.iss?.includes(shopHost)) {
      return { valid: false, error: 'Issuer mismatch' };
    }

    return { valid: true, payload, shop: shopHost };
  } catch (err) {
    return {
      valid: false,
      error: err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token',
    };
  }
}

function requireSessionToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized', detail: 'Missing token' });
  }

  const token = auth.slice(7);
  const result = verifySessionToken(token);

  if (!result.valid) {
    return res.status(401).json({ error: 'Unauthorized', detail: result.error });
  }

  req.shopifyShop = result.shop;
  req.shopifyToken = token;
  req.shopifyPayload = result.payload;
  next();
}

// ===========================================
// DATA PERSISTENCE
// ===========================================

async function saveShop(shop, accessToken, scope) {
  const shopData = {
    shop,
    accessToken,
    scope,
    installedAt: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
    tokenVersion: 1,
  };

  await storage.set(`shop:${shop}`, shopData);
  await storage.set(`token:${shop}`, { accessToken, createdAt: new Date().toISOString() });

  logger.info('Shop data saved', { shop });
  return shopData;
}

async function getShop(shop) {
  return await storage.get(`shop:${shop}`);
}

async function getAccessTokenForShop(shop) {
  const tokenData = await storage.get(`token:${shop}`);
  if (!tokenData) {
    const shopData = await getShop(shop);
    return shopData?.accessToken || null;
  }
  return tokenData.accessToken;
}

async function deleteShop(shop) {
  await storage.delete(`shop:${shop}`);
  await storage.delete(`token:${shop}`);
  logger.info('Shop data deleted', { shop });
}

async function hasValidToken(shop) {
  return !!(await getAccessTokenForShop(shop));
}

// ===========================================
// IDEMPOTENT WEBHOOK PROCESSING
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

// ===========================================
// SHOPIFY API FUNCTIONS
// ===========================================

async function exchangeTokenForOfflineToken(shop, sessionToken) {
  const response = await axios.post(
    `https://${shop}/admin/oauth/access_token`,
    {
      client_id: CONFIG.shopify.apiKey,
      client_secret: CONFIG.shopify.apiSecret,
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: sessionToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      requested_token_type: 'urn:shopify:params:oauth:token-type:offline-access-token',
    },
    { timeout: CONFIG.timeouts.axios }
  );
  return {
    accessToken: response.data.access_token,
    scope: response.data.scope,
  };
}

async function registerWebhooks(shop, accessToken) {
  if (!CONFIG.webhookBaseUrl) {
    logger.warn('WEBHOOK_BASE_URL not set — skipping webhook registration', { shop });
    return;
  }

  const base = `https://${shop}/admin/api/${CONFIG.shopify.apiVersion}`;
  const headers = {
    'X-Shopify-Access-Token': accessToken,
    'Content-Type': 'application/json',
  };

  const topics = [
    'orders/create',
    'orders/updated',
    'customers/create',
    'customers/updated',
    'products/update',
    'app/uninstalled',
  ];

  for (const topic of topics) {
    const address = `${CONFIG.webhookBaseUrl}/webhooks/${topic}`;
    try {
      await axios.post(
        `${base}/webhooks.json`,
        { webhook: { topic, address, format: 'json' } },
        { headers, timeout: CONFIG.timeouts.axios }
      );
      logger.info('Webhook registered', { shop, topic });
    } catch (error) {
      if (error.response?.status === 422) {
        logger.info('Webhook already exists', { shop, topic });
      } else {
        logger.error('Failed to register webhook', error, { shop, topic });
      }
    }
  }
}

// ===========================================
// BUBBLE.IO INTEGRATION
// ===========================================

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
        headers: { 'Content-Type': 'application/json' },
      });

      logger.info('Data sent to Bubble successfully', { endpoint, status: response.status });
      return { success: true, response: response.data };
    } catch (error) {
      logger.error(`Bubble request failed (attempt ${attempt}/${retries})`, error, {
        endpoint,
        status: error.response?.status,
      });

      // Treat Bubble API Connector parsing errors as non-fatal
      if (
        error.response?.status === 400 &&
        error.response?.data?.message?.includes('Error parsing data from Apiconnector')
      ) {
        logger.warn('Bubble API Connector parsing error — treating as non-fatal', { endpoint });
        return { success: true, warning: 'API Connector parsing error ignored', partialSuccess: true };
      }

      if (error.response?.status >= 400 && error.response?.status < 500) {
        return { success: false, error: `Bubble returned ${error.response.status}`, permanent: true };
      }

      if (attempt === retries) {
        return { success: false, error: error.message, attempts: retries };
      }

      const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

function bubbleWfUrl(workflowName) {
  if (CONFIG.bubble.wfBaseUrl) return `${CONFIG.bubble.wfBaseUrl}/${workflowName}`;
  return CONFIG.bubble.apiEndpoint;
}

// ===========================================
// HEALTH CHECKS
// ===========================================

async function checkStorageHealth() {
  try {
    const testKey = 'health:check';
    const testValue = { timestamp: Date.now() };
    await storage.set(testKey, testValue);
    const retrieved = await storage.get(testKey);
    await storage.delete(testKey);
    if (retrieved && retrieved.timestamp === testValue.timestamp) return { healthy: true };
    return { healthy: false, message: 'Storage test failed' };
  } catch (error) {
    return { healthy: false, message: error.message };
  }
}

// ===========================================
// ROUTES — HEALTH & STATUS
// ===========================================

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'KatiCRM Shopify Middleware', version: '4.0.0' });
});

app.get('/health', async (req, res) => {
  const storageHealth = await checkStorageHealth();

  res.status(storageHealth.healthy ? 200 : 503).json({
    status: storageHealth.healthy ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    service: 'KatiCRM Shopify Middleware',
    version: '4.0.0',
    uptime: process.uptime(),
    storage: storageHealth,
  });
});

app.get('/ready', (req, res) => {
  res.json({ ready: true, timestamp: new Date().toISOString() });
});

app.get('/ping', (req, res) => {
  res.send('pong');
});

// ===========================================
// ROUTES — SESSION TOKEN AUTH
// ===========================================

/**
 * POST /api/shopify/auth
 *
 * Called by the React embedded app on startup.
 * Verifies the App Bridge session token, exchanges it for an offline access token
 * via Shopify Token Exchange, stores it, and registers webhooks.
 *
 * Headers:  Authorization: Bearer <session_token>
 * Response: { shop, accessTokenStored: true, source: 'cache' | 'token_exchange' }
 */
app.post('/api/shopify/auth', requireSessionToken, async (req, res) => {
  const shop = req.shopifyShop;

  try {
    // Return early if we already have a stored token (avoid duplicate exchanges)
    const existingToken = await getAccessTokenForShop(shop);
    if (existingToken) {
      logger.info('Auth: returning cached token', { shop });
      return res.json({ shop, accessTokenStored: true, source: 'cache' });
    }

    // Exchange the App Bridge session token for a persistent offline access token
    logger.info('Auth: exchanging session token for offline token', { shop });
    const { accessToken, scope } = await exchangeTokenForOfflineToken(shop, req.shopifyToken);
    await saveShop(shop, accessToken, scope);

    // Background: notify Bubble and register webhooks (non-blocking)
    setImmediate(async () => {
      try {
        await sendToBubble(CONFIG.bubble.apiEndpoint, {
          shop,
          access_token: accessToken,
          scope,
          status: 'connected',
          source: 'token_exchange',
          installed_at: new Date().toISOString(),
        });
        await registerWebhooks(shop, accessToken);
      } catch (err) {
        logger.error('Post-auth background task failed', err, { shop });
      }
    });

    return res.json({ shop, accessTokenStored: true, source: 'token_exchange' });
  } catch (error) {
    logger.error('Auth error', error, { shop });
    return res.status(500).json({ error: 'Authentication failed', detail: error.message });
  }
});

/**
 * POST /api/shopify/graphql
 *
 * GraphQL proxy — forwards queries and mutations from the React app or Bubble
 * to the Shopify Admin GraphQL API using the stored offline access token.
 *
 * Headers:  Authorization: Bearer <session_token>
 *           Content-Type: application/json
 * Body:     { query: "...", variables: {} }
 * Response: Shopify GraphQL response verbatim (including data.errors if present)
 */
app.post('/api/shopify/graphql', requireSessionToken, async (req, res) => {
  const shop = req.shopifyShop;
  const { query, variables } = req.body;

  if (!query) {
    return res.status(400).json({ error: 'Missing query field in request body' });
  }

  try {
    const accessToken = await getAccessTokenForShop(shop);
    if (!accessToken) {
      return res.status(401).json({
        error: 'Shop not authenticated. Call POST /api/shopify/auth first.',
        shop,
      });
    }

    const response = await axios.post(
      `https://${shop}/admin/api/${CONFIG.shopify.apiVersion}/graphql.json`,
      { query, variables },
      {
        headers: {
          'X-Shopify-Access-Token': accessToken,
          'Content-Type': 'application/json',
        },
        timeout: CONFIG.timeouts.axios,
      }
    );

    // Forward Shopify's status code and body verbatim (includes data.errors for partial errors)
    return res.status(response.status).json(response.data);
  } catch (error) {
    const status = error.response?.status || 502;
    const body = error.response?.data || { error: error.message };
    logger.error('GraphQL proxy error', error, { shop });
    return res.status(status).json(body);
  }
});

// ===========================================
// ROUTES — APP LIFECYCLE WEBHOOKS
// ===========================================

/**
 * POST /webhooks/app/uninstalled
 * Cleans up stored tokens and notifies Bubble when the app is uninstalled.
 */
app.post('/webhooks/app/uninstalled', async (req, res) => {
  const shop = req.get('X-Shopify-Shop-Domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  const rawBody = req.body;

  if (!hmac || !verifyWebhook(rawBody, hmac)) {
    return res.status(401).send('Unauthorized');
  }

  res.status(200).send('Acknowledged');

  setImmediate(async () => {
    try {
      logger.info('App uninstalled webhook received', { shop });
      if (shop) await deleteShop(shop);
      await sendToBubble(bubbleWfUrl('shopify_app_uninstalled1'), {
        shop,
        received_at: new Date().toISOString(),
      });
    } catch (err) {
      logger.error('Uninstall webhook error', err, { shop });
    }
  });
});

// ===========================================
// ROUTES — ORDER WEBHOOKS
// ===========================================

app.post('/webhooks/orders/create', async (req, res) => {
  const shop = req.get('X-Shopify-Shop-Domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  const webhookId = req.get('X-Shopify-Webhook-Id');
  const rawBody = req.body;

  const parsed = parseWebhookBody(rawBody);
  if (!parsed.ok) return res.status(400).send('Invalid JSON');
  if (!hmac || !verifyWebhook(rawBody, hmac)) return res.status(401).send('Unauthorized');

  res.status(200).send('Acknowledged');

  setImmediate(async () => {
    try {
      await processWebhookIdempotent(webhookId || `orders_create_${shop}_${Date.now()}`, async () => {
        logger.info('Order created', { shop, orderId: parsed.body.id });
        await sendToBubble(bubbleWfUrl('wh_shopify_order_created'), {
          ...parsed.body,
          shop,
          received_at: new Date().toISOString(),
        });
      });
    } catch (err) {
      logger.error('Order create webhook error', err, { shop });
    }
  });
});

app.post('/webhooks/orders/updated', async (req, res) => {
  const shop = req.get('X-Shopify-Shop-Domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  const webhookId = req.get('X-Shopify-Webhook-Id');
  const rawBody = req.body;

  const parsed = parseWebhookBody(rawBody);
  if (!parsed.ok) return res.status(400).send('Invalid JSON');
  if (!hmac || !verifyWebhook(rawBody, hmac)) return res.status(401).send('Unauthorized');

  res.status(200).send('Acknowledged');

  setImmediate(async () => {
    try {
      await processWebhookIdempotent(webhookId || `orders_updated_${shop}_${Date.now()}`, async () => {
        logger.info('Order updated', { shop, orderId: parsed.body.id });
        await sendToBubble(bubbleWfUrl('wh_shopify_order_updated'), {
          ...parsed.body,
          shop,
          received_at: new Date().toISOString(),
        });
      });
    } catch (err) {
      logger.error('Order updated webhook error', err, { shop });
    }
  });
});

// ===========================================
// ROUTES — CUSTOMER WEBHOOKS
// ===========================================

app.post('/webhooks/customers/create', async (req, res) => {
  const shop = req.get('X-Shopify-Shop-Domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  const webhookId = req.get('X-Shopify-Webhook-Id');
  const rawBody = req.body;

  const parsed = parseWebhookBody(rawBody);
  if (!parsed.ok) return res.status(400).send('Invalid JSON');
  if (!hmac || !verifyWebhook(rawBody, hmac)) return res.status(401).send('Unauthorized');

  res.status(200).send('Acknowledged');

  setImmediate(async () => {
    try {
      await processWebhookIdempotent(webhookId || `customers_create_${shop}_${Date.now()}`, async () => {
        logger.info('Customer created', { shop, customerId: parsed.body.id });
        await sendToBubble(bubbleWfUrl('wh_shopify_customer_created'), {
          ...parsed.body,
          shop,
          received_at: new Date().toISOString(),
        });
      });
    } catch (err) {
      logger.error('Customer create webhook error', err, { shop });
    }
  });
});

app.post('/webhooks/customers/updated', async (req, res) => {
  const shop = req.get('X-Shopify-Shop-Domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  const webhookId = req.get('X-Shopify-Webhook-Id');
  const rawBody = req.body;

  const parsed = parseWebhookBody(rawBody);
  if (!parsed.ok) return res.status(400).send('Invalid JSON');
  if (!hmac || !verifyWebhook(rawBody, hmac)) return res.status(401).send('Unauthorized');

  res.status(200).send('Acknowledged');

  setImmediate(async () => {
    try {
      await processWebhookIdempotent(webhookId || `customers_updated_${shop}_${Date.now()}`, async () => {
        logger.info('Customer updated', { shop, customerId: parsed.body.id });
        await sendToBubble(bubbleWfUrl('wh_shopify_customer_updated'), {
          ...parsed.body,
          shop,
          received_at: new Date().toISOString(),
        });
      });
    } catch (err) {
      logger.error('Customer updated webhook error', err, { shop });
    }
  });
});

// ===========================================
// ROUTES — PRODUCT WEBHOOKS
// ===========================================

app.post('/webhooks/products/update', async (req, res) => {
  const shop = req.get('X-Shopify-Shop-Domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  const webhookId = req.get('X-Shopify-Webhook-Id');
  const rawBody = req.body;

  const parsed = parseWebhookBody(rawBody);
  if (!parsed.ok) return res.status(400).send('Invalid JSON');
  if (!hmac || !verifyWebhook(rawBody, hmac)) return res.status(401).send('Unauthorized');

  res.status(200).send('Acknowledged');

  setImmediate(async () => {
    try {
      await processWebhookIdempotent(webhookId || `products_update_${shop}_${Date.now()}`, async () => {
        logger.info('Product updated', { shop, productId: parsed.body.id });
        await sendToBubble(bubbleWfUrl('wh_shopify_product_updated'), {
          ...parsed.body,
          shop,
          received_at: new Date().toISOString(),
        });
      });
    } catch (err) {
      logger.error('Product update webhook error', err, { shop });
    }
  });
});

// ===========================================
// ROUTES — GDPR MANDATORY WEBHOOKS
// ===========================================

app.post('/webhooks/customers/data_request', async (req, res) => {
  const shop = req.get('X-Shopify-Shop-Domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  const rawBody = req.body;

  const parsed = parseWebhookBody(rawBody);
  if (!parsed.ok) return res.status(400).send('Invalid JSON');
  if (!hmac || !verifyWebhook(rawBody, hmac)) return res.status(401).send('Unauthorized');

  res.status(200).send('Acknowledged');

  setImmediate(async () => {
    try {
      await sendToBubble(CONFIG.bubble.gdpr.dataRequest, {
        shop: shop || parsed.body.shop_domain,
        customer_email: parsed.body.customer?.email,
        received_at: new Date().toISOString(),
      });
    } catch (err) {
      logger.error('GDPR data_request webhook error', err);
    }
  });
});

app.post('/webhooks/customers/redact', async (req, res) => {
  const shop = req.get('X-Shopify-Shop-Domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  const rawBody = req.body;

  const parsed = parseWebhookBody(rawBody);
  if (!parsed.ok) return res.status(400).send('Invalid JSON');
  if (!hmac || !verifyWebhook(rawBody, hmac)) return res.status(401).send('Unauthorized');

  res.status(200).send('Will be redacted');

  setImmediate(async () => {
    try {
      await sendToBubble(CONFIG.bubble.gdpr.customerRedact, {
        shop: shop || parsed.body.shop_domain,
        customer_email: parsed.body.customer?.email,
        received_at: new Date().toISOString(),
      });
    } catch (err) {
      logger.error('GDPR customers/redact webhook error', err);
    }
  });
});

app.post('/webhooks/shop/redact', async (req, res) => {
  const shop = req.get('X-Shopify-Shop-Domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  const rawBody = req.body;

  const parsed = parseWebhookBody(rawBody);
  if (!parsed.ok) return res.status(400).send('Invalid JSON');
  if (!hmac || !verifyWebhook(rawBody, hmac)) return res.status(401).send('Unauthorized');

  const shopDomain = shop || parsed.body.shop_domain;
  if (shopDomain) await deleteShop(shopDomain);

  res.status(200).send('Will be redacted');

  setImmediate(async () => {
    try {
      await sendToBubble(CONFIG.bubble.gdpr.shopRedact, {
        shop: shopDomain,
        received_at: new Date().toISOString(),
      });
    } catch (err) {
      logger.error('GDPR shop/redact webhook error', err);
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
  logger.info(`${signal} received, shutting down gracefully`);

  server.close(() => {
    if (CONFIG.redis.enabled && redisClient) {
      redisClient.quit(() => process.exit(0));
    } else {
      process.exit(0);
    }
  });

  setTimeout(() => process.exit(1), CONFIG.timeouts.gracefulShutdown);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ===========================================
// SERVER STARTUP
// ===========================================

const server = app.listen(PORT, () => {
  logger.info('KatiCRM Shopify Middleware v4.0 started', {
    port: PORT,
    env: NODE_ENV,
    storage: CONFIG.redis.enabled ? 'redis' : 'memory',
    webhookBaseUrl: CONFIG.webhookBaseUrl || 'not set (webhook registration disabled)',
  });
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║   KatiCRM Shopify Middleware v4.0 — Session Token Auth  ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`📡 Listening on port ${PORT}`);
  console.log('');
  console.log('🔐 Auth:      POST /api/shopify/auth     (session token → offline token)');
  console.log('🔍 GraphQL:   POST /api/shopify/graphql  (queries + mutations proxy)');
  console.log('');
  console.log('📦 Webhooks:');
  console.log('   POST /webhooks/app/uninstalled');
  console.log('   POST /webhooks/orders/create');
  console.log('   POST /webhooks/orders/updated');
  console.log('   POST /webhooks/customers/create');
  console.log('   POST /webhooks/customers/updated');
  console.log('   POST /webhooks/products/update');
  console.log('   POST /webhooks/customers/data_request  (GDPR)');
  console.log('   POST /webhooks/customers/redact        (GDPR)');
  console.log('   POST /webhooks/shop/redact             (GDPR)');
  console.log('');
  console.log(`💾 Storage:   ${CONFIG.redis.enabled ? 'Redis' : 'In-memory (tokens lost on restart)'}`);
  console.log(`🔗 Webhooks:  ${CONFIG.webhookBaseUrl || 'WEBHOOK_BASE_URL not set — auto-registration disabled'}`);
  console.log('');
});
