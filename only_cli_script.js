// Enhanced CDN Authentication Worker with Bot Protection - REFINED VERSION
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const hostname = url.hostname;
    const isDirectWorkerAccess = hostname.includes('workers.dev');
    
    // ============ DEBUG & MONITORING ENDPOINTS ============
    if (url.pathname === '/env-debug') {
      return new Response(JSON.stringify({
        // Show config with masking
        SECRET_KEY_SET: env.SECRET_KEY ? "***MASKED***" : "NOT_SET",
        ALLOWED_CLIENTS_COUNT: parseClientList(env.ALLOWED_CLIENTS).length,
        AUTH_ENABLED: env.AUTH_ENABLED === "true",
        BOT_PROTECTION_ENABLED: env.BOT_PROTECTION_ENABLED === "true",
        RATE_LIMIT_MAX: parseInt(env.RATE_LIMIT_MAX || "100"),
        ORIGIN_URL_SET: env.ORIGIN_BASE_URL ? "***MASKED***" : "NOT_SET",
        request: {
          hostname: hostname,
          path: url.pathname,
          source: isDirectWorkerAccess ? 'direct-worker' : 'custom-domain',
          ip: request.headers.get('CF-Connecting-IP'),
          userAgent: request.headers.get('User-Agent')?.substring(0, 50) || 'none'
        }
      }, null, 2), {
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }
    
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({
        status: "healthy",
        timestamp: new Date().toISOString(),
        worker: "cdn-auth",
        version: "2.2"
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // ============ CONFIGURATION FROM ENV VARS ============
    // Core Authentication
    const SECRET_KEY = env.SECRET_KEY;
    const ALLOWED_CLIENTS = parseClientList(env.ALLOWED_CLIENTS);
    const AUTH_ENABLED = env.AUTH_ENABLED === "true";
    const SIGNATURE_TTL = parseInt(env.SIGNATURE_TTL || "300");
    
    // Bot Protection
    const BOT_PROTECTION_ENABLED = env.BOT_PROTECTION_ENABLED === "true";
    const BLOCK_VERIFIED_BOTS = env.BLOCK_VERIFIED_BOTS === "true";
    
    // Rate Limiting
    const RATE_LIMIT_WINDOW = parseInt(env.RATE_LIMIT_WINDOW || "60");
    const RATE_LIMIT_MAX = parseInt(env.RATE_LIMIT_MAX || "100");
    const BOT_RATE_LIMIT_MAX = parseInt(env.BOT_RATE_LIMIT_MAX || "10");
    
    // Path Configuration
    const SKIP_PATHS = parsePathList(env.SKIP_PATHS || '["/health", "/status", "/env-debug"]');
    const API_PATHS = parsePathList(env.API_PATHS || '["/api/", "/v1/", "/v2/"]');
    
    // ============ VALIDATE CONFIGURATION ============
    if (!SECRET_KEY || SECRET_KEY.length < 32) {
      console.error('Invalid SECRET_KEY configuration');
      return new Response(JSON.stringify({
        error: "Server configuration error",
        message: "SECRET_KEY must be at least 32 characters"
      }), { status: 500 });
    }
    
    if (ALLOWED_CLIENTS.length === 0) {
      console.warn('No ALLOWED_CLIENTS configured');
    }
    
    // ============ SKIP AUTH FOR SPECIFIED PATHS ============
    if (SKIP_PATHS.some(path => url.pathname.startsWith(path))) {
      console.log(`Skipping auth for path: ${url.pathname}`);
      const newHeaders = new Headers(request.headers);
      newHeaders.set('X-CDN-Skip-Auth', 'true');
      return fetch(new Request(request, { headers: newHeaders }));
    }
    
    // ============ BOT DETECTION (Before Authentication) ============
    if (BOT_PROTECTION_ENABLED) {
      const botCheck = detectBot(request);
      
      if (botCheck.isBot) {
        console.log(`Bot detected: ${botCheck.type} - ${botCheck.userAgent}`);
        
        // Block verified bots if configured
        if (botCheck.type === 'verified' && BLOCK_VERIFIED_BOTS) {
          return new Response(JSON.stringify({
            error: "Bot access not allowed",
            code: "verified_bot_blocked"
          }), { status: 403 });
        }
        
        // Block high-score bots
        if (botCheck.type === 'high_score' && botCheck.score > 50) {
          return new Response(JSON.stringify({
            error: "Suspicious traffic detected",
            code: "high_bot_score"
          }), { status: 403 });
        }
        
        // Apply stricter rate limits for bots
        const botRateLimit = await checkRateLimit(
          `bot:${botCheck.type}:${request.headers.get('CF-Connecting-IP')}`,
          env,
          BOT_RATE_LIMIT_MAX,
          RATE_LIMIT_WINDOW
        );
        
        if (!botRateLimit.allowed) {
          return new Response(JSON.stringify({
            error: "Bot rate limit exceeded",
            code: "bot_rate_limit"
          }), { status: 429 });
        }
      }
    }
    
    // ============ EMERGENCY AUTH DISABLE ============
    if (!AUTH_ENABLED) {
      console.warn('AUTH DISABLED - Emergency mode active');
      const newHeaders = new Headers(request.headers);
      newHeaders.set('X-CDN-Auth-Disabled', 'true');
      newHeaders.set('X-CDN-Source', isDirectWorkerAccess ? 'direct-worker' : 'custom-domain');
      return fetch(new Request(request, { headers: newHeaders }));
    }
    
    // ============ VALIDATE AUTHENTICATION ============
    const authResult = await validateAuth(request, {
      secretKey: SECRET_KEY,
      allowedClients: ALLOWED_CLIENTS,
      signatureTTL: SIGNATURE_TTL,
      kvStore: env.AUTH_STORE
    });
    
    if (!authResult.valid) {
      await logAuthFailure(request, authResult, env, isDirectWorkerAccess);
      
      // Generic error messages for security
      const errorMessages = {
        missing_headers: "Invalid request format",
        invalid_client_id: "Authentication failed",
        timestamp_expired: "Request expired",
        invalid_signature: "Authentication failed",
        nonce_replay: "Duplicate request detected"
      };
      
      return new Response(JSON.stringify({
        error: errorMessages[authResult.reason] || "Authentication failed",
        timestamp: new Date().toISOString()
      }), {
        status: 401,
        headers: {
          'Content-Type': 'application/json',
          'X-CDN-Source': isDirectWorkerAccess ? 'direct-worker' : 'custom-domain'
        }
      });
    }
    
    // ============ RATE LIMITING FOR AUTHENTICATED REQUESTS ============
    const rateLimit = await checkRateLimit(
      `client:${authResult.clientId}`,
      env,
      RATE_LIMIT_MAX,
      RATE_LIMIT_WINDOW
    );
    
    if (!rateLimit.allowed) {
      return new Response(JSON.stringify({
        error: "Rate limit exceeded",
        retryAfter: rateLimit.retryAfter
      }), {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': rateLimit.retryAfter.toString(),
          'X-RateLimit-Limit': rateLimit.limit.toString(),
          'X-RateLimit-Remaining': '0'
        }
      });
    }
    
    // ============ FORWARD TO ORIGIN (CORRECTED VERSION) ============
    const originUrl = 'https://tunnel-login.support-noreply.help' + url.pathname + url.search;
    
    const newHeaders = new Headers(request.headers);
    
    // 🔥 CRITICAL: Add the headers your tunnel/origin expects
    newHeaders.set('X-CDN-Verified', 'true');
    newHeaders.set('X-Client-Key', authResult.clientId || 'worker-authenticated');
    newHeaders.set('X-Timestamp', Date.now().toString());
    newHeaders.set('X-Nonce', crypto.randomUUID());
    
    // Generate a signature for the tunnel to verify
    const signatureData = `WORKER:${authResult.clientId}:${Date.now()}:${crypto.randomUUID()}`;
    const signature = await generateHMACSHA256(signatureData, SECRET_KEY);
    newHeaders.set('X-Signature', signature);
    
    // Clean original auth headers
    ['X-Client-Key', 'X-Signature', 'X-Timestamp', 'X-Nonce'].forEach(h => {
      if (!h.startsWith('X-CDN-')) newHeaders.delete(h);
    });
    
    // Add identification headers
    newHeaders.set('X-CDN-Client-ID', authResult.clientId);
    newHeaders.set('X-CDN-Authenticated', 'yes');
    newHeaders.set('X-CDN-Source', isDirectWorkerAccess ? 'direct-worker' : 'worker-proxied');
    newHeaders.set('X-CDN-Auth-Time', Date.now().toString());
    newHeaders.set('X-CDN-RateLimit-Remaining', rateLimit.remaining.toString());
    newHeaders.set('Host', 'login.support-noreply.help'); // Important for tunnel routing
    
    // Preserve original IP info
    const originalIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    newHeaders.set('X-Original-IP', originalIp);
    newHeaders.set('X-Forwarded-For', originalIp);
    
    // User-Agent normalization for WAF compatibility
    const originalUA = request.headers.get('User-Agent') || '';
    if (originalUA.includes('python') || originalUA.includes('go-http-client') || 
        originalUA.includes('curl') || originalUA.includes('wget')) {
      newHeaders.set('User-Agent', 'Mozilla/5.0 (compatible; API-Client/1.0)');
    }
    
    const fetchOptions = {
      method: request.method,
      headers: newHeaders,
      body: request.body,
      redirect: 'manual',
      cf: {
        cacheKey: `${isDirectWorkerAccess ? 'worker' : 'domain'}:${url.pathname}:${authResult.clientId}`,
        cacheEverything: false,
        scrapeShield: !isDirectWorkerAccess ? false : undefined,
        polish: !isDirectWorkerAccess ? 'off' : undefined
      }
    };
    
    const modifiedRequest = new Request(originUrl, fetchOptions);
    
    // Log successful auth
    await logAuthSuccess(request, authResult, env, rateLimit, isDirectWorkerAccess);
    
    // Forward to origin
    return fetch(modifiedRequest);
  }
};

// ============ HELPER FUNCTIONS ============

function parseClientList(input) {
  if (!input) return [];
  
  if (Array.isArray(input)) {
    return input;
  }
  
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      try { 
        return JSON.parse(trimmed); 
      } catch (e) { 
        console.error('Error parsing client list JSON:', e);
      }
    }
    return trimmed.split(',').map(s => s.trim()).filter(s => s);
  }
  
  console.error('Unexpected input type for parseClientList:', typeof input, input);
  return [];
}

function parsePathList(input) {
  if (!input) return ['/health', '/status', '/env-debug'];
  
  if (Array.isArray(input)) {
    return input;
  }
  
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      try { 
        return JSON.parse(trimmed); 
      } catch (e) { 
        console.error('Error parsing path list JSON:', e);
      }
    }
    return trimmed.split(',').map(s => s.trim()).filter(s => s);
  }
  
  console.error('Unexpected input type for parsePathList:', typeof input, input);
  return ['/health', '/status', '/env-debug'];
}

function detectBot(request) {
  const userAgent = request.headers.get('User-Agent') || '';
  const cfBotScore = parseInt(request.headers.get('cf-bot-score') || '0');
  const isVerifiedBot = request.headers.get('cf-client-bot') === '1';
  
  if (isVerifiedBot) {
    return {
      isBot: true,
      type: 'verified',
      userAgent: userAgent.substring(0, 100),
      score: cfBotScore
    };
  }
  
  if (cfBotScore > 30) {
    return {
      isBot: true,
      type: 'high_score',
      userAgent: userAgent.substring(0, 100),
      score: cfBotScore
    };
  }
  
  const botPatterns = [
    'bot', 'crawl', 'spider', 'scrape', 'scrapy',
    'python', 'java/', 'go-http-client', 'okhttp',
    'curl', 'wget', 'libwww', 'libweb', 'http-client',
    'headless', 'selenium', 'puppeteer', 'playwright'
  ];
  
  const lowerUA = userAgent.toLowerCase();
  for (const pattern of botPatterns) {
    if (lowerUA.includes(pattern)) {
      return {
        isBot: true,
        type: 'pattern',
        userAgent: userAgent.substring(0, 100),
        score: cfBotScore,
        pattern: pattern
      };
    }
  }
  
  return {
    isBot: false,
    type: 'human',
    userAgent: userAgent.substring(0, 100),
    score: cfBotScore
  };
}

async function validateAuth(request, config) {
  const { secretKey, allowedClients, signatureTTL, kvStore } = config;
  
  const clientId = request.headers.get('X-Client-Key');
  const signature = request.headers.get('X-Signature');
  const timestamp = request.headers.get('X-Timestamp');
  const nonce = request.headers.get('X-Nonce');
  
  if (!clientId || !signature || !timestamp || !nonce) {
    return { valid: false, reason: 'missing_headers' };
  }
  
  if (!allowedClients.includes(clientId)) {
    return { valid: false, reason: 'invalid_client_id', clientId };
  }
  
  const requestTime = parseInt(timestamp);
  if (isNaN(requestTime) || Math.abs(Date.now() - requestTime) > (signatureTTL * 1000)) {
    return { valid: false, reason: 'timestamp_expired' };
  }
  
  if (kvStore) {
    const nonceKey = `nonce:${clientId}:${nonce}`;
    const existing = await kvStore.get(nonceKey);
    if (existing) {
      return { valid: false, reason: 'nonce_replay' };
    }
    await kvStore.put(nonceKey, 'used', { expirationTtl: signatureTTL });
  }
  
  const url = new URL(request.url);
  const pathWithQuery = url.pathname + url.search;
  const dataToSign = `${request.method.toUpperCase()}:${pathWithQuery}:${timestamp}:${nonce}`;
  
  const expectedSignature = await generateHMACSHA256(dataToSign, secretKey);
  if (!constantTimeCompare(signature, expectedSignature)) {
    return { valid: false, reason: 'invalid_signature' };
  }
  
  return { valid: true, clientId, timestamp: requestTime, nonce };
}

async function generateHMACSHA256(data, secretKey) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secretKey);
  const messageData = encoder.encode(data);
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function constantTimeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  
  const aBuf = new TextEncoder().encode(a);
  const bBuf = new TextEncoder().encode(b);
  let result = 0;
  
  for (let i = 0; i < aBuf.length; i++) {
    result |= aBuf[i] ^ bBuf[i];
  }
  return result === 0;
}

async function checkRateLimit(key, env, max, window) {
  if (!env.AUTH_STORE) {
    return { allowed: true, limit: max, remaining: max, retryAfter: '0' };
  }
  
  const now = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(now / window) * window;
  const rateKey = `ratelimit:${key}:${windowStart}`;
  
  let current = 0;
  try {
    const stored = await env.AUTH_STORE.get(rateKey);
    current = stored ? parseInt(stored) : 0;
  } catch (e) {
    console.error('Rate limit read error:', e);
  }
  
  if (current >= max) {
    const resetTime = windowStart + window;
    return {
      allowed: false,
      limit: max,
      remaining: 0,
      retryAfter: (resetTime - now).toString()
    };
  }
  
  try {
    await env.AUTH_STORE.put(rateKey, (current + 1).toString(), {
      expirationTtl: window * 2
    });
  } catch (e) {
    console.error('Rate limit write error:', e);
  }
  
  return {
    allowed: true,
    limit: max,
    remaining: max - (current + 1),
    retryAfter: '0'
  };
}

async function logAuthFailure(request, authResult, env, isDirectWorkerAccess) {
  const log = {
    type: 'auth_failure',
    source: isDirectWorkerAccess ? 'direct-worker' : 'custom-domain',
    timestamp: new Date().toISOString(),
    reason: authResult.reason,
    clientId: authResult.clientId || 'unknown',
    ip: request.headers.get('CF-Connecting-IP'),
    path: new URL(request.url).pathname,
    hostname: new URL(request.url).hostname
  };
  
  console.error('Auth failed:', log);
  
  if (env.AUTH_STORE) {
    try {
      await env.AUTH_STORE.put(
        `log:fail:${Date.now()}`,
        JSON.stringify(log),
        { expirationTtl: 604800 }
      );
    } catch (e) {
      console.error('Failed to log auth failure:', e);
    }
  }
}

async function logAuthSuccess(request, authResult, env, rateLimit, isDirectWorkerAccess) {
  const log = {
    type: 'auth_success',
    source: isDirectWorkerAccess ? 'direct-worker' : 'custom-domain',
    timestamp: new Date().toISOString(),
    clientId: authResult.clientId,
    ip: request.headers.get('CF-Connecting-IP'),
    path: new URL(request.url).pathname,
    hostname: new URL(request.url).hostname,
    rateLimitRemaining: rateLimit.remaining
  };
  
  console.log('Auth success:', log.clientId);
  
  if (env.AUTH_STORE) {
    try {
      await env.AUTH_STORE.put(
        `log:success:${Date.now()}`,
        JSON.stringify(log),
        { expirationTtl: 2592000 }
      );
    } catch (e) {
      console.error('Failed to log auth success:', e);
    }
  }
}