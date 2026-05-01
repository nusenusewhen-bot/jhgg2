const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const UserAgent = require('user-agents');
const WebSocket = require('ws');
const http = require('http');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

const activeBots = new Map();

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

const getHeaders = (cookie, csrfToken = '') => {
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
    'X-CSRF-TOKEN': csrfToken,
    'Cookie': `.ROBLOSECURITY=${cookie}`,
    'RBX-Super-Props': Buffer.from(JSON.stringify(SUPER_PROPERTIES)).toString('base64'),
    'X-Requested-With': 'XMLHttpRequest'
  };
};

const validateCookie = async (cookie) => {
  try {
    const headers = getHeaders(cookie);
    const response = await axios.get('https://auth.roblox.com/v1/user/passwords', {
      headers,
      validateStatus: (status) => status === 200 || status === 403,
      timeout: 10000
    });
    
    if (response.status === 403) {
      const csrfToken = response.headers['x-csrf-token'];
      if (!csrfToken) return { valid: false, error: 'No CSRF token received' };
      
      headers['X-CSRF-TOKEN'] = csrfToken;
      
      const verifyResponse = await axios.get('https://users.roblox.com/v1/users/authenticated', {
        headers,
        validateStatus: (status) => status === 200 || status === 401,
        timeout: 10000
      });
      
      if (verifyResponse.status === 200) {
        return { 
          valid: true, 
          csrfToken, 
          user: verifyResponse.data 
        };
      }
    }
    
    return { valid: false, error: 'Invalid or expired cookie' };
  } catch (error) {
    return { valid: false, error: error.message };
  }
};

const extractPlaceId = (link) => {
  const patterns = [
    /games\/(\d+)\//,
    /place\?id=(\d+)/,
    /privateServer\/.*\?placeId=(\d+)/,
    /(\d{8,})/
  ];
  
  for (const pattern of patterns) {
    const match = link.match(pattern);
    if (match) return match[1];
  }
  return null;
};

const extractAccessCode = (link) => {
  const match = link.match(/privateServerLinkCode=([a-zA-Z0-9-]+)/);
  return match ? match[1] : null;
};

const getGameTicket = async (cookie, csrfToken) => {
  const headers = getHeaders(cookie, csrfToken);
  
  const ticketResponse = await axios.post(
    'https://auth.roblox.com/v1/authentication-ticket',
    {},
    {
      headers,
      validateStatus: (status) => status === 200 || status === 403,
      timeout: 15000
    }
  );
  
  if (ticketResponse.status === 403) {
    const newCsrf = ticketResponse.headers['x-csrf-token'];
    headers['X-CSRF-TOKEN'] = newCsrf;
    
    const retry = await axios.post(
      'https://auth.roblox.com/v1/authentication-ticket',
      {},
      { headers, timeout: 15000 }
    );
    
    return { ticket: retry.headers['rbx-authentication-ticket'], csrfToken: newCsrf };
  }
  
  return { 
    ticket: ticketResponse.headers['rbx-authentication-ticket'], 
    csrfToken 
  };
};

const getGameDetails = async (placeId, cookie, csrfToken) => {
  const headers = getHeaders(cookie, csrfToken);
  const response = await axios.get(
    `https://games.roblox.com/v1/games/multiget-place-details?placeIds=${placeId}`,
    { headers, timeout: 10000 }
  );
  return response.data[0];
};

const maintainPresence = async (botId, cookie, csrfToken, placeId, accessCode, ws) => {
  const presenceInterval = setInterval(async () => {
    try {
      const headers = getHeaders(cookie, csrfToken);
      
      await axios.post(
        'https://presence.roblox.com/v1/presence/register-game-presence',
        {
          placeId: parseInt(placeId),
          accessCode: accessCode || undefined
        },
        { headers, timeout: 10000 }
      );
      
      ws.send(JSON.stringify({
        type: 'presence',
        message: 'Maintaining game presence',
        timestamp: new Date().toISOString()
      }));
    } catch (error) {
      ws.send(JSON.stringify({
        type: 'error',
        message: `Presence error: ${error.message}`,
        timestamp: new Date().toISOString()
      }));
    }
  }, 30000);

  activeBots.get(botId).intervals.push(presenceInterval);
};

const startBot = async (botId, cookie, privateServerLink, ws) => {
  try {
    ws.send(JSON.stringify({ type: 'status', message: 'Validating cookie format...' }));
    
    if (!cookie || cookie.length < 100) {
      ws.send(JSON.stringify({ type: 'error', message: 'Cookie too short or missing' }));
      return;
    }

    ws.send(JSON.stringify({ type: 'status', message: 'Authenticating with Roblox...' }));
    
    const validation = await validateCookie(cookie);
    if (!validation.valid) {
      ws.send(JSON.stringify({ type: 'error', message: validation.error }));
      return;
    }

    ws.send(JSON.stringify({ 
      type: 'status', 
      message: `Authenticated as ${validation.user.name}` 
    }));

    const placeId = extractPlaceId(privateServerLink);
    if (!placeId) {
      ws.send(JSON.stringify({ type: 'error', message: 'Could not extract Place ID from link' }));
      return;
    }

    ws.send(JSON.stringify({ type: 'status', message: `Place ID: ${placeId}` }));

    const accessCode = extractAccessCode(privateServerLink);
    const gameDetails = await getGameDetails(placeId, cookie, validation.csrfToken);

    ws.send(JSON.stringify({ 
      type: 'status', 
      message: `Target: ${gameDetails.name}` 
    }));

    ws.send(JSON.stringify({ type: 'status', message: 'Generating auth ticket...' }));
    
    const ticketData = await getGameTicket(cookie, validation.csrfToken);
    
    ws.send(JSON.stringify({ type: 'status', message: 'Joining private server...' }));

    const joinHeaders = getHeaders(cookie, ticketData.csrfToken);
    joinHeaders['RBX-Authentication-Ticket'] = ticketData.ticket;
    joinHeaders['Referer'] = privateServerLink;

    const joinResponse = await axios.post(
      'https://gamejoin.roblox.com/v1/join-game-instance',
      {
        placeId: parseInt(placeId),
        isTeleport: false,
        gameId: accessCode || undefined,
        accessCode: accessCode || undefined
      },
      {
        headers: joinHeaders,
        validateStatus: (status) => status === 200 || status === 403,
        timeout: 20000
      }
    );

    if (joinResponse.status === 403) {
      const newCsrf = joinResponse.headers['x-csrf-token'];
      joinHeaders['X-CSRF-TOKEN'] = newCsrf;
      
      const retryJoin = await axios.post(
        'https://gamejoin.roblox.com/v1/join-game-instance',
        {
          placeId: parseInt(placeId),
          isTeleport: false,
          gameId: accessCode || undefined,
          accessCode: accessCode || undefined
        },
        { headers: joinHeaders, timeout: 20000 }
      );
      
      ws.send(JSON.stringify({ 
        type: 'success', 
        message: 'Bot joined successfully',
        data: retryJoin.data
      }));
    } else {
      ws.send(JSON.stringify({ 
        type: 'success', 
        message: 'Bot joined successfully',
        data: joinResponse.data
      }));
    }

    ws.send(JSON.stringify({ type: 'status', message: 'Starting presence heartbeat...' }));
    
    maintainPresence(botId, cookie, ticketData.csrfToken, placeId, accessCode, ws);

    activeBots.get(botId).status = 'active';
    activeBots.get(botId).user = validation.user;
    activeBots.get(botId).game = gameDetails;

  } catch (error) {
    ws.send(JSON.stringify({ 
      type: 'error', 
      message: error.response?.data?.errors?.[0]?.message || error.message 
    }));
  }
};

wss.on('connection', (ws) => {
  const botId = uuidv4();
  
  activeBots.set(botId, {
    ws,
    status: 'initializing',
    intervals: [],
    user: null,
    game: null
  });

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      
      if (data.action === 'start') {
        if (!data.cookie || !data.privateServerLink) {
          ws.send(JSON.stringify({ type: 'error', message: 'Missing cookie or private server link' }));
          return;
        }
        
        activeBots.get(botId).status = 'starting';
        await startBot(botId, data.cookie, data.privateServerLink, ws);
      }
      
      if (data.action === 'leave') {
        const bot = activeBots.get(botId);
        if (bot) {
          bot.intervals.forEach(clearInterval);
          bot.intervals = [];
          bot.status = 'disconnected';
          
          ws.send(JSON.stringify({ 
            type: 'status', 
            message: 'Bot disconnected from server' 
          }));
          
          setTimeout(() => {
            ws.close();
            activeBots.delete(botId);
          }, 1000);
        }
      }
    } catch (error) {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
    }
  });

  ws.on('close', () => {
    const bot = activeBots.get(botId);
    if (bot) {
      bot.intervals.forEach(clearInterval);
      activeBots.delete(botId);
    }
  });

  ws.send(JSON.stringify({ 
    type: 'connected', 
    botId,
    message: 'Connected. Ready to initialize.' 
  }));
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'operational', 
    activeBots: activeBots.size,
    timestamp: new Date().toISOString() 
  });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`WebSocket: ws://localhost:${PORT}/ws`);
});
