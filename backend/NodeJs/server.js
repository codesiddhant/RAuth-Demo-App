require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const { RauthProvider } = require('rauth-provider');

const app = express();
app.use(express.json());

// Initialize RauthProvider
RauthProvider.init({
  rauth_api_key: process.env.RAUTH_API_KEY,
  app_id: process.env.RAUTH_APP_ID,
  webhook_secret: process.env.RAUTH_WEBHOOK_SECRET,
  webhook_url: process.env.RAUTH_WEBHOOK_URL,
});

// Webhook endpoint
app.post('/rauth/webhook', RauthProvider.webhookHandler());

// Session initialization
app.post('/api/login/init', async (req, res) => {
  try {
    const { phone } = req.body;
    const initResult = await RauthProvider.initSession(phone, req.headers);
    res.json({ ...initResult });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Session verification
app.post('/api/login', async (req, res) => {
  try {
    const { sessionToken, userPhone } = req.body;
    const isVerified = await RauthProvider.verifySession(sessionToken, userPhone);
    if (!isVerified) {
      return res.status(401).json({ error: 'Phone number not verified' });
    }
    const jwtToken = jwt.sign({ userPhone, sessionToken }, process.env.JWT_SECRET);
    res.json({ jwtToken });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Protected route
app.get('/api/protected', async (req, res) => {
  try {
    const jwtToken = req.headers.authorization?.replace('Bearer ', '');
    const decoded = jwt.verify(jwtToken, process.env.JWT_SECRET);
    const isRevoked = await RauthProvider.isSessionRevoked(decoded.sessionToken);
    if (isRevoked) {
      return res.status(401).json({ error: 'Session revoked. Please log in again.' });
    }
    res.json({ message: 'Protected route accessed', user: decoded.userPhone });
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Health check endpoint for Rauth API
app.get('/api/rauth/health', async (req, res) => {
  try {
    const isHealthy = await RauthProvider.checkApiHealth();
    res.json({ rauthApiHealthy: isHealthy });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 