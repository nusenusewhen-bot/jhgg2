const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const UserAgent = require('user-agents');
const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

const PORT = process.env.PORT || 3000;
const LOG_FILE = path.join(__dirname, 'bot_logs.txt');

const logToFile = (message) => {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] ${message}\n`;
  fs.appendFileSync(LOG_FILE, logEntry);
  console.log(logEntry.trim());
};

const logError = (context, error) => {
  const errorDetails = error.response ? 
    `Status: ${error.response.status}, Data: ${JSON.stringify(error.response.data)}` : 
    error.message;
  logToFile(`ERROR [${context}]: ${errorDetails}`);
  return errorDetails;
};

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
  logToFile(`STEP 1: Starting cookie validation (length: ${cookie.length})`);
  
  try {
    const headers = getHeaders(cookie);
    logToFile('STEP 2: Sending initial auth request to roblox.com/v1/user/passwords');
    
    const response = await axios.get('https://auth.roblox.com/v1/user/passwords', {
      headers,
      validateStatus: (status) => status === 200 || status === 403,
      timeout: 15000
    });
    
    logToFile(`STEP 3: Initial response status: ${response.status}`);
    
    if (response.status === 403) {
      const csrfToken = response.headers['x-csrf-token'];
      logToFile(`STEP 4: Got CSRF token: ${csrfToken ? 'YES' : 'NO'}`);
      
      if (!csrfToken) {
        logToFile('STEP 4-FAIL: No CSRF token in 403 response headers');
        return { valid: false, error: 'No CSRF token received from Roblox' };
      }
      
      headers['X-CSRF-TOKEN'] = csrfToken;
      logToFile('STEP 5: Sending authenticated user verification request');
      
      const verifyResponse = await axios.get('https://users.roblox.com/v1/users/authenticated', {
        headers,
        validateStatus: (status) => status === 200 || status === 401,
        timeout: 15000
      });
      
      logToFile(`STEP 6: Verification response status: ${verifyResponse.status}`);
      
      if (verifyResponse.status === 200) {
        logToFile(`STEP 7: SUCCESS - Authenticated as ${verifyResponse.data.name} (ID: ${verifyResponse.data.id})`);
        return { 
          valid: true, 
          csrfToken, 
          user: verifyResponse.data 
        };
      }
      
      logToFile('STEP 7-FAIL: Verification returned non-200 status');
      return { valid: false, error: 'Cookie verification failed (401/403)' };
    }
    
    logToFile('STEP 3-FAIL: Initial response was not 403, unexpected behavior');
    return { valid: false, error: 'Unexpected auth response from Roblox' };
  } catch (error) {
    logError('Cookie Validation', error);
    return { valid: false, error: `Network/Request Error: ${error.message}` };
  }
};

const extractPlaceId = (link) => {
  logToFile(`PARSING: Extracting Place ID from link: ${link.substring(0, 60)}...`);
  
  const patterns = [
    /games\/(\d+)\//,
    /place\?id=(\d+)/,
    /privateServer\/.*\?placeId=(\d+)/,
    /(\d{8,})/
  ];
  
  for (const pattern of patterns) {
    const match = link.match(pattern);
    if (match) {
      logToFile(`PARSING: Found Place ID: ${match[1]}`);
      return match[1];
    }
  }
  
  logToFile('PARSING-FAIL: No Place ID pattern matched');
  return null;
};

const extractAccessCode = (link) => {
  const match = link.match(/privateServerLinkCode=([a-zA-Z0-9-]+)/);
  const code = match ? match[1] : null;
  logToFile(`PARSING: Access code ${code ? 'found' : 'NOT found'}`);
  return code;
};

const getGameTicket = async (cookie, csrfToken) => {
  logToFile('TICKET: Requesting authentication ticket...');
  
  try {
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
    
    logToFile(`TICKET: Response status ${ticketResponse.status}`);
    
    if (ticketResponse.status === 403) {
      const newCsrf = ticketResponse.headers['x-csrf-token'];
      logToFile(`TICKET: Got new CSRF token, retrying...`);
      
      headers['X-CSRF-TOKEN'] = newCsrf;
      
      const retry = await axios.post(
        'https://auth.roblox.com/v1/authentication-ticket',
        {},
        { headers, timeout: 15000 }
      );
      
      const ticket = retry.headers['rbx-authentication-ticket'];
      logToFile(`TICKET: Retry success, ticket ${ticket ? 'received' : 'MISSING'}`);
      
      return { ticket, csrfToken: newCsrf };
    }
    
    const ticket = ticketResponse.headers['rbx-authentication-ticket'];
    logToFile(`TICKET: First attempt success, ticket ${ticket ? 'received' : 'MISSING'}`);
    
    return { ticket, csrfToken };
  } catch (error) {
    logError('Get Game Ticket', error);
    throw error;
  }
};

const getGameDetails = async (placeId, cookie, csrfToken) => {
  logToFile(`GAME: Fetching details for Place ID ${placeId}`);
  
  try {
    const headers = getHeaders(cookie, csrfToken);
    const response = await axios.get(
      `https://games.roblox.com/v1/games/multiget-place-details?placeIds=${placeId}`,
      { headers, timeout: 15000 }
    );
    
    const details = response.data[0];
    logToFile(`GAME: Found "${details.name}" (Universe: ${details.universeId})`);
    return details;
  } catch (error) {
    logError('Get Game Details', error);
    throw error;
  }
};

const maintainPresence = (botId, cookie, csrfToken, placeId, accessCode, ws) => {
  logToFile(`PRESENCE: Starting heartbeat every 30 seconds`);
  
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
        message: 'Heartbeat: Bot active in game',
        timestamp: new Date().toISOString()
      }));
    } catch (error) {
      const errMsg = error.response?.data?.errors?.[0]?.message || error.message;
      logToFile(`PRESENCE-ERROR: ${errMsg}`);
      
      ws.send(JSON.stringify({
        type: 'error',
        message: `Presence heartbeat failed: ${errMsg}`,
        timestamp: new Date().toISOString()
      }));
    }
  }, 30000);

  activeBots.get(botId).intervals.push(presenceInterval);
};

const startBot = async (botId, cookie, privateServerLink, ws) => {
  logToFile(`========== BOT START: ${botId} ==========`);
  
  try {
    ws.send(JSON.stringify({ type: 'status', message: '[1/6] Validating cookie format...' }));
    
    if (!cookie || cookie.length < 100) {
      const err = 'Cookie too short or empty';
      logToFile(`VALIDATION-FAIL: ${err}`);
      ws.send(JSON.stringify({ type: 'error', message: err }));
      return;
    }

    ws.send(JSON.stringify({ type: 'status', message: '[2/6] Authenticating with Roblox API...' }));
    const validation = await validateCookie(cookie);
    
    if (!validation.valid) {
      logToFile(`AUTH-FAIL: ${validation.error}`);
      ws.send(JSON.stringify({ type: 'error', message: `Auth failed: ${validation.error}` }));
      return;
    }

    ws.send(JSON.stringify({ 
      type: 'status', 
      message: `[3/6] Logged in as ${validation.user.name}` 
    }));

    const placeId = extractPlaceId(privateServerLink);
    if (!placeId) {
      const err = 'Could not extract Place ID from private server link';
      logToFile(`PARSE-FAIL: ${err}`);
      ws.send(JSON.stringify({ type: 'error', message: err }));
      return;
    }

    ws.send(JSON.stringify({ type: 'status', message: `[4/6] Place ID: ${placeId}` }));

    const accessCode = extractAccessCode(privateServerLink);
    const gameDetails = await getGameDetails(placeId, cookie, validation.csrfToken);

    ws.send(JSON.stringify({ 
      type: 'status', 
      message: `[5/6] Target: ${gameDetails.name}` 
    }));

    ws.send(JSON.stringify({ type: 'status', message: '[6/6] Generating auth ticket & joining...' }));
    
    const ticketData = await getGameTicket(cookie, validation.csrfToken);
    
    if (!ticketData.ticket) {
      const err = 'Failed to obtain authentication ticket';
      logToFile(`TICKET-FAIL: ${err}`);
      ws.send(JSON.stringify({ type: 'error', message: err }));
      return;
    }

    const joinHeaders = getHeaders(cookie, ticketData.csrfToken);
    joinHeaders['RBX-Authentication-Ticket'] = ticketData.ticket;
    joinHeaders['Referer'] = privateServerLink;

    logToFile('JOIN: Sending join request to gamejoin.roblox.com');
    
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

    logToFile(`JOIN: Response status ${joinResponse.status}`);

    if (joinResponse.status === 403) {
      const newCsrf = joinResponse.headers['x-csrf-token'];
      logToFile('JOIN: 403 received, retrying with new CSRF...');
      
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
      
      logToFile(`JOIN-RETRY: Success! Status ${retryJoin.status}`);
      
      ws.send(JSON.stringify({ 
        type: 'success', 
        message: 'Bot joined and staying in server',
        data: retryJoin.data
      }));
    } else {
      logToFile(`JOIN: Success on first attempt`);
      
      ws.send(JSON.stringify({ 
        type: 'success', 
        message: 'Bot joined and staying in server',
        data: joinResponse.data
      }));
    }

    ws.send(JSON.stringify({ type: 'status', message: 'Starting presence heartbeat (30s intervals)...' }));
    
    maintainPresence(botId, cookie, ticketData.csrfToken, placeId, accessCode, ws);

    activeBots.get(botId).status = 'active';
    activeBots.get(botId).user = validation.user;
    activeBots.get(botId).game = gameDetails;
    
    logToFile(`========== BOT ACTIVE: ${botId} ==========`);

  } catch (error) {
    const errMsg = error.response?.data?.errors?.[0]?.message || error.message;
    logToFile(`CRITICAL-ERROR: ${errMsg}`);
    ws.send(JSON.stringify({ 
      type: 'error', 
      message: `Critical error: ${errMsg}` 
    }));
  }
};

wss.on('connection', (ws, req) => {
  const botId = uuidv4();
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  
  logToFile(`WS-CONNECT: Client ${ip} connected, assigned ${botId}`);
  
  activeBots.set(botId, {
    ws,
    status: 'initializing',
    intervals: [],
    user: null,
    game: null,
    ip
  });

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      logToFile(`WS-MESSAGE: ${botId} sent action="${data.action}"`);
      
      if (data.action === 'start') {
        if (!data.cookie || !data.privateServerLink) {
          const err = 'Missing cookie or private server link in message';
          logToFile(`START-FAIL: ${err}`);
          ws.send(JSON.stringify({ type: 'error', message: err }));
          return;
        }
        
        activeBots.get(botId).status = 'starting';
        await startBot(botId, data.cookie, data.privateServerLink, ws);
      }
      
      if (data.action === 'leave') {
        logToFile(`LEAVE: ${botId} requested disconnect`);
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
            logToFile(`LEAVE: ${botId} cleaned up`);
          }, 1000);
        }
      }
    } catch (error) {
      logToFile(`WS-ERROR: ${botId} - ${error.message}`);
      ws.send(JSON.stringify({ type: 'error', message: `Invalid message: ${error.message}` }));
    }
  });

  ws.on('close', (code, reason) => {
    logToFile(`WS-CLOSE: ${botId} closed (code: ${code}, reason: ${reason || 'none'})`);
    const bot = activeBots.get(botId);
    if (bot) {
      bot.intervals.forEach(clearInterval);
      activeBots.delete(botId);
    }
  });

  ws.on('error', (error) => {
    logToFile(`WS-ERROR: ${botId} - ${error.message}`);
  });

  ws.send(JSON.stringify({ 
    type: 'connected', 
    botId,
    message: 'Connected to server. Ready to initialize.' 
  }));
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'operational', 
    activeBots: activeBots.size,
    timestamp: new Date().toISOString() 
  });
});

app.get('/api/logs', (req, res) => {
  try {
    const logs = fs.readFileSync(LOG_FILE, 'utf8');
    res.type('text/plain').send(logs);
  } catch {
    res.status(404).send('No logs available yet');
  }
});

server.listen(PORT, () => {
  logToFile(`SERVER-START: Running on port ${PORT}`);
  logToFile(`SERVER-START: WebSocket endpoint ws://localhost:${PORT}/ws`);
  logToFile(`SERVER-START: Logs endpoint http://localhost:${PORT}/api/logs`);
});
