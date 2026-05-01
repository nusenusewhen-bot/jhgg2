const express = require('express');
const axios = require('axios');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const UserAgent = require('user-agents');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const ROBLOX_API = 'https://apis.roblox.com';
const AUTH_API = 'https://auth.roblox.com';
const GAMES_API = 'https://games.roblox.com';
const THUMBNAILS_API = 'https://thumbnails.roblox.com';

const SUPER_PROPERTIES = {
  os: 'Windows',
  browser: 'Chrome',
  device: '',
  browserVersion: '120.0.0.0',
  osVersion: '10.0',
  platform: 'Web',
  robloxBrowserTracker: uuidv4(),
  robloxLocale: 'en_us',
  gameLocale: 'en_us',
  resolution: '1920x1080',
  avatarType: 'R15',
  avatarHeadType: 'DynamicHead',
  avatarScaleType: 'ProportionsNormal',
  isDarkMode: true,
  authenticationType: 'AuthToken',
  requestType: 'Login'
};

const getHeaders = (cookie) => {
  const userAgent = new UserAgent();
  return {
    'User-Agent': userAgent.toString(),
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Content-Type': 'application/json',
    'Origin': 'https://www.roblox.com',
    'Referer': 'https://www.roblox.com/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-site',
    'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"Windows"',
    'X-CSRF-TOKEN': '',
    'Cookie': `.ROBLOSECURITY=${cookie}`,
    'RBX-Super-Props': Buffer.from(JSON.stringify(SUPER_PROPERTIES)).toString('base64')
  };
};

const validateCookie = async (cookie) => {
  try {
    const headers = getHeaders(cookie);
    const response = await axios.get(`${AUTH_API}/v1/user/passwords`, {
      headers,
      validateStatus: (status) => status === 200 || status === 403
    });
    
    if (response.status === 403) {
      const csrfToken = response.headers['x-csrf-token'];
      headers['X-CSRF-TOKEN'] = csrfToken;
      
      const verifyResponse = await axios.get(`${AUTH_API}/v1/user/passwords`, {
        headers,
        validateStatus: (status) => status === 200 || status === 401
      });
      
      if (verifyResponse.status === 200) return { valid: true, csrfToken };
    }
    
    return { valid: false, error: 'Invalid or expired cookie' };
  } catch (error) {
    return { valid: false, error: error.message };
  }
};

const getUserInfo = async (cookie, csrfToken) => {
  const headers = getHeaders(cookie);
  headers['X-CSRF-TOKEN'] = csrfToken;
  
  const response = await axios.get('https://users.roblox.com/v1/users/authenticated', { headers });
  return response.data;
};

const extractPlaceId = (privateServerLink) => {
  const patterns = [
    /games\/(\d+)\//,
    /place\?id=(\d+)/,
    /private-server\/.*\?placeId=(\d+)/,
    /(\d{8,})/ 
  ];
  
  for (const pattern of patterns) {
    const match = privateServerLink.match(pattern);
    if (match) return match[1];
  }
  
  return null;
};

const getGameDetails = async (placeId, cookie, csrfToken) => {
  const headers = getHeaders(cookie);
  headers['X-CSRF-TOKEN'] = csrfToken;
  
  const universeResponse = await axios.get(
    `${GAMES_API}/v1/games/multiget-place-details?placeIds=${placeId}`,
    { headers }
  );
  
  return universeResponse.data[0];
};

const joinPrivateServer = async (placeId, privateServerLink, cookie, csrfToken) => {
  const headers = getHeaders(cookie);
  headers['X-CSRF-TOKEN'] = csrfToken;
  headers['Referer'] = privateServerLink;
  
  const accessCode = extractAccessCode(privateServerLink);
  
  const joinRequest = {
    placeId: parseInt(placeId),
    isTeleport: false,
    launchData: '',
    accessCode: accessCode || undefined
  };
  
  const response = await axios.post(
    `${ROBLOX_API}/game-auth/v1/game-joints/join`,
    joinRequest,
    { 
      headers,
      validateStatus: (status) => status === 200 || status === 403
    }
  );
  
  if (response.status === 403) {
    const newCsrf = response.headers['x-csrf-token'];
    headers['X-CSRF-TOKEN'] = newCsrf;
    
    const retryResponse = await axios.post(
      `${ROBLOX_API}/game-auth/v1/game-joints/join`,
      joinRequest,
      { headers }
    );
    
    return retryResponse.data;
  }
  
  return response.data;
};

const extractAccessCode = (link) => {
  const match = link.match(/privateServerLinkCode=([a-zA-Z0-9-]+)/);
  return match ? match[1] : null;
};

app.post('/api/authenticate', [
  body('cookie')
    .trim()
    .isLength({ min: 100 })
    .withMessage('Cookie must be at least 100 characters')
    .matches(/^[A-Za-z0-9+/=]+$/)
    .withMessage('Invalid cookie format'),
  body('privateServerLink')
    .trim()
    .isURL()
    .withMessage('Must be a valid URL')
    .matches(/roblox\.com/)
    .withMessage('Must be a Roblox URL')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false, 
      errors: errors.array() 
    });
  }

  const { cookie, privateServerLink } = req.body;
  
  try {
    const cookieValidation = await validateCookie(cookie);
    if (!cookieValidation.valid) {
      return res.status(401).json({
        success: false,
        error: 'Authentication failed',
        details: cookieValidation.error
      });
    }

    const userInfo = await getUserInfo(cookie, cookieValidation.csrfToken);
    const placeId = extractPlaceId(privateServerLink);
    
    if (!placeId) {
      return res.status(400).json({
        success: false,
        error: 'Could not extract Place ID from private server link'
      });
    }

    const gameDetails = await getGameDetails(placeId, cookie, cookieValidation.csrfToken);
    
    const joinResult = await joinPrivateServer(
      placeId, 
      privateServerLink, 
      cookie, 
      cookieValidation.csrfToken
    );

    res.json({
      success: true,
      user: {
        id: userInfo.id,
        name: userInfo.name,
        displayName: userInfo.displayName
      },
      game: {
        placeId,
        name: gameDetails.name,
        universeId: gameDetails.universeId
      },
      joinStatus: 'Successfully initiated join request',
      serverDetails: joinResult,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Bot operation failed:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Bot operation failed',
      details: error.response?.data?.errors?.[0]?.message || error.message
    });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'operational', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Roblox Cookie Bot server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
