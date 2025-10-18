const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const querystring = require('querystring');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration from environment variables
const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY;
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET;
const BUBBLE_API_ENDPOINT = process.env.BUBBLE_API_ENDPOINT;
const SCOPES = 'read_customers,write_customers,read_orders,write_orders,read_products,write_products,read_inventory,write_inventory,read_locations';

// Function to verify HMAC
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
        </style>
      </head>
      <body>
        <h1>🛡️ Shopify OAuth Middleware</h1>
        <p>This service handles OAuth authentication between Shopify and Bubble.io</p>
        
        <h2>Available Endpoints:</h2>
        
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
        
        <h2>Status:</h2>
        <p>✅ Middleware is running correctly</p>
        <p>⚙️ Configured for: ${BUBBLE_API_ENDPOINT ? 'Bubble endpoint configured' : 'Bubble endpoint NOT configured'}</p>
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
  console.log('=================================');
});
