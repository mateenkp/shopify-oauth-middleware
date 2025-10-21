const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const querystring = require('querystring');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON bodies (needed for webhooks)
app.use(express.json());

// Configuration from environment variables
const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY;
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET;
const BUBBLE_API_ENDPOINT = process.env.BUBBLE_API_ENDPOINT;
const SCOPES = 'read_customers,write_customers,read_orders,write_orders,read_products,write_products,read_inventory,write_inventory,read_locations';

// Function to verify HMAC for OAuth
function verifyHmac(query, hmac) {
  // Create a copy of query without hmac and signature
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
    
  return hash === hmac;
}

// Function to verify webhook HMAC signatures
function verifyWebhook(data, hmac) {
  const hash = crypto
    .createHmac('sha256', SHOPIFY_API_SECRET)
    .update(JSON.stringify(data), 'utf8')
    .digest('base64');
  
  return hash === hmac;
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    message: 'Shopify OAuth Middleware is running'
  });
});

// Route 1: Initiate OAuth Installation
app.get('/install', (req, res) => {
  const shop = req.query.shop;
  
  if (!shop) {
    return res.status(400).send('Missing shop parameter. Please provide ?shop=your-store.myshopify.com');
  }
  
  // Generate random state for security
  const state = crypto.randomBytes(16).toString('hex');
  const redirectUri = `${process.env.APP_URL}/callback`;
  
  // Build Shopify authorization URL
  const installUrl = `https://${shop}/admin/oauth/authorize?` +
    `client_id=${SHOPIFY_API_KEY}&` +
    `scope=${SCOPES}&` +
    `redirect_uri=${redirectUri}&` +
    `state=${state}`;
  
  console.log('Initiating OAuth for shop:', shop);
  console.log('Redirect URI:', redirectUri);
  
  // In production, store state in Redis/database
  // For now, we'll skip state verification
  
  res.redirect(installUrl);
});

// Route 2: OAuth Callback (Shopify redirects here after authorization)
app.get('/callback', async (req, res) => {
  const { shop, code, hmac, state } = req.query;
  
  console.log('Received callback from Shopify');
  console.log('Shop:', shop);
  console.log('Code received:', code ? 'Yes' : 'No');
  
  // Verify HMAC signature
  if (!verifyHmac(req.query, hmac)) {
    console.error('HMAC validation failed');
    return res.status(400).send('HMAC validation failed. This request may not be from Shopify.');
  }
  
  console.log('HMAC validated successfully');
  
  // Exchange authorization code for access token
  try {
    console.log('Exchanging code for access token...');
    
    const tokenResponse = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code: code
      }
    );
    
    const accessToken = tokenResponse.data.access_token;
    const scope = tokenResponse.data.scope;
    
    console.log('Access token obtained successfully');
    console.log('Granted scopes:', scope);
    
    // Send token to Bubble
    console.log('Sending token to Bubble:', BUBBLE_API_ENDPOINT);
    
    await axios.post(BUBBLE_API_ENDPOINT, {
      shop_domain: shop,
      access_token: accessToken,
      scope: scope,
      connected_at: new Date().toISOString()
    });
    
    console.log('Token stored in Bubble successfully');
    
    // Redirect to success page in Bubble
    const successUrl = process.env.BUBBLE_SUCCESS_URL || `https://your-katicrm.bubbleapps.io/shopify-connected?shop=${shop}&success=true`;
    res.redirect(successUrl);
    
  } catch (error) {
    console.error('OAuth error:', error.response?.data || error.message);
    
    // Redirect to error page
    const errorUrl = process.env.BUBBLE_ERROR_URL || `https://your-katicrm.bubbleapps.io/shopify-connected?success=false&error=${encodeURIComponent(error.message)}`;
    res.redirect(errorUrl);
  }
});

// ==========================================
// GDPR COMPLIANCE WEBHOOKS
// ==========================================

// Webhook 1: Customer Data Request
app.post('/webhooks/customers/data_request', async (req, res) => {
  const shop = req.get('X-Shopify-Shop-Domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  
  console.log('📋 Customer data request received from:', shop);
  
  // Verify webhook authenticity
  if (!verifyWebhook(req.body, hmac)) {
    console.error('❌ Webhook verification failed for data_request');
    return res.status(401).send('Unauthorized');
  }
  
  console.log('✅ Webhook verified successfully');
  console.log('Customer email:', req.body.customer?.email);
  console.log('Customer ID:', req.body.customer?.id);
  
  // Log for compliance records
  console.log('Data request details:', {
    shop: shop,
    customer_email: req.body.customer?.email,
    customer_id: req.body.customer?.id,
    orders_requested: req.body.orders_requested,
    timestamp: new Date().toISOString()
  });
  
  // Optional: Forward to Bubble for processing
  if (BUBBLE_API_ENDPOINT) {
    try {
      await axios.post(`${BUBBLE_API_ENDPOINT}/gdpr/data_request`, {
        shop: shop,
        customer_email: req.body.customer?.email,
        customer_id: req.body.customer?.id,
        orders_requested: req.body.orders_requested,
        timestamp: new Date().toISOString()
      });
      console.log('📤 Data request forwarded to Bubble');
    } catch (error) {
      console.error('Error forwarding to Bubble:', error.message);
    }
  }
  
  res.status(200).send('Data request received and logged');
});

// Webhook 2: Customer Redact
app.post('/webhooks/customers/redact', async (req, res) => {
  const shop = req.get('X-Shopify-Shop-Domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  
  console.log('🗑️ Customer redaction request received from:', shop);
  
  // Verify webhook authenticity
  if (!verifyWebhook(req.body, hmac)) {
    console.error('❌ Webhook verification failed for customer redact');
    return res.status(401).send('Unauthorized');
  }
  
  console.log('✅ Webhook verified successfully');
  console.log('Customer to redact:', req.body.customer?.email);
  
  // Log for compliance records
  console.log('Customer redaction details:', {
    shop: shop,
    customer_email: req.body.customer?.email,
    customer_id: req.body.customer?.id,
    orders_to_redact: req.body.orders_to_redact,
    timestamp: new Date().toISOString()
  });
  
  // Optional: Forward to Bubble for processing
  if (BUBBLE_API_ENDPOINT) {
    try {
      await axios.post(`${BUBBLE_API_ENDPOINT}/gdpr/customer_redact`, {
        shop: shop,
        customer_email: req.body.customer?.email,
        customer_id: req.body.customer?.id,
        orders_to_redact: req.body.orders_to_redact,
        timestamp: new Date().toISOString()
      });
      console.log('📤 Redaction request forwarded to Bubble');
    } catch (error) {
      console.error('Error forwarding to Bubble:', error.message);
    }
  }
  
  res.status(200).send('Customer data will be redacted');
});

// Webhook 3: Shop Redact (Store uninstalled)
app.post('/webhooks/shop/redact', async (req, res) => {
  const shop = req.get('X-Shopify-Shop-Domain');
  const hmac = req.get('X-Shopify-Hmac-Sha256');
  
  console.log('🏪 Shop redaction request received from:', shop);
  
  // Verify webhook authenticity
  if (!verifyWebhook(req.body, hmac)) {
    console.error('❌ Webhook verification failed for shop redact');
    return res.status(401).send('Unauthorized');
  }
  
  console.log('✅ Webhook verified successfully');
  
  // Log for compliance records
  console.log('Shop redaction details:', {
    shop: shop,
    shop_id: req.body.shop_id,
    shop_domain: req.body.shop_domain,
    timestamp: new Date().toISOString()
  });
  
  // Optional: Forward to Bubble for processing
  if (BUBBLE_API_ENDPOINT) {
    try {
      await axios.post(`${BUBBLE_API_ENDPOINT}/gdpr/shop_redact`, {
        shop: shop,
        shop_id: req.body.shop_id,
        shop_domain: req.body.shop_domain,
        timestamp: new Date().toISOString()
      });
      console.log('📤 Shop redaction request forwarded to Bubble');
    } catch (error) {
      console.error('Error forwarding to Bubble:', error.message);
    }
  }
  
  res.status(200).send('Shop data will be redacted');
});

// ==========================================
// END GDPR COMPLIANCE WEBHOOKS
// ==========================================

// Root endpoint with instructions
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Shopify OAuth Middleware</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
          h1 { color: #008060; }
          code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
          .endpoint { background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 4px solid #008060; }
          .webhook { background: #fff3cd; padding: 15px; margin: 10px 0; border-left: 4px solid #ffc107; }
        </style>
      </head>
      <body>
        <h1>🛡️ Shopify OAuth Middleware</h1>
        <p>This service handles OAuth authentication between Shopify and Bubble.io</p>
        
        <h2>OAuth Endpoints:</h2>
        
        <div class="endpoint">
          <h3>GET /health</h3>
          <p>Health check endpoint</p>
          <p><a href="/health">Test it now</a></p>
        </div>
        
        <div class="endpoint">
          <h3>GET /install?shop=[store-name].myshopify.com</h3>
          <p>Initiates OAuth flow for a Shopify store</p>
          <p>Example: <code>/install?shop=my-test-store.myshopify.com</code></p>
        </div>
        
        <div class="endpoint">
          <h3>GET /callback</h3>
          <p>OAuth callback endpoint (used by Shopify)</p>
          <p>This is called automatically by Shopify during installation</p>
        </div>
        
        <h2>GDPR Compliance Webhooks:</h2>
        
        <div class="webhook">
          <h3>POST /webhooks/customers/data_request</h3>
          <p>Receives customer data requests (GDPR compliance)</p>
        </div>
        
        <div class="webhook">
          <h3>POST /webhooks/customers/redact</h3>
          <p>Receives customer data deletion requests (GDPR compliance)</p>
        </div>
        
        <div class="webhook">
          <h3>POST /webhooks/shop/redact</h3>
          <p>Receives shop data deletion requests when app is uninstalled (GDPR compliance)</p>
        </div>
        
        <h2>Status:</h2>
        <p>✅ Middleware is running correctly</p>
        <p>⚙️ Configured for: ${BUBBLE_API_ENDPOINT ? 'Bubble endpoint configured' : 'Bubble endpoint NOT configured'}</p>
        <p>🔐 GDPR webhooks: Active and ready</p>
      </body>
    </html>
  `);
});

// Start server
app.listen(PORT, () => {
  console.log('=================================');
  console.log('Shopify OAuth Middleware Started');
  console.log(`Port: ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log('🔐 GDPR webhooks enabled');
  console.log('=================================');
});
