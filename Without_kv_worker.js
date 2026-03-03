// ============ PRODUCTION ENVIRONMENT CONFIGURATION ============
/*
REQUIRED ENVIRONMENT VARIABLES:
1. SECRET_KEY=32+ character random string (Plain Text)
2. CLIENT_SECRETS={"client-1":"secret1","web-client":"secret2"} (Plain Text - valid JSON)
3. ALLOWED_CLIENTS=["client-1","web-client"] (JSON array)
4. TUNNEL_URL=https://your-origin-server.com (Plain Text)
5. AUTH_ENABLED=true (Plain Text)

OPTIONAL:
- BOT_PROTECTION_ENABLED=true/false
- RATE_LIMIT_MAX=100
- RATE_LIMIT_WINDOW=60
- SIGNATURE_TTL=300
- ADMIN_TOKEN=your-admin-secret
- SKIP_PATHS=["/health","/status"] (JSON)
- AUTH_STORE=KV namespace binding (OPTIONAL - system works without it)
*/

// ============ AUTH CALLBACK HANDLERS ============

async function handleAuthCallback(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');
  
  if (!token) {
    return errorResponse(400, 'Missing token parameter');
  }
  
  // Validate the token
  const authResult = await validateBearerToken(token, env);
  if (!authResult.valid) {
    return errorResponse(401, 'Invalid token');
  }
  
  // Set secure HTTP-only cookie
  const cookie = `cdn_auth_token=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600`;
  
  // Redirect to home page
  return new Response('', {
    status: 302,
    headers: {
      'Location': '/',
      'Set-Cookie': cookie,
      'Cache-Control': 'no-store'
    }
  });
}

function handleLogout() {
  // Clear the auth cookie
  const cookie = 'cdn_auth_token=; HttpOnly; Secure; SameSite=Strict; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
  
  return new Response('', {
    status: 302,
    headers: {
      'Location': '/',
      'Set-Cookie': cookie,
      'Cache-Control': 'no-store'
    }
  });
}

// ============ COOKIE HELPER FUNCTION ============

function getCookieValue(request, cookieName) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return null;
  
  const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
    const [name, value] = cookie.trim().split('=');
    if (name && value) acc[name] = decodeURIComponent(value);
    return acc;
  }, {});
  
  return cookies[cookieName] || null;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    const userAgent = request.headers.get('User-Agent') || '';
    const startTime = Date.now();
    
    // ============ SECURITY LAYER 1: WAF ENHANCEMENT ============
    const securityCheck = performSecurityChecks(request, env);
    if (securityCheck.block) {
      await logSecurityEvent('security_block', request, env, securityCheck);
      return securityBlockResponse(securityCheck);
    }
    
    // ============ PUBLIC ENDPOINTS (NO AUTH REQUIRED) ============
    const skipPaths = parsePathList(env.SKIP_PATHS || '["/health","/status","/robots.txt"]');
    if (skipPaths.some(path => url.pathname.startsWith(path))) {
      return handlePublicRequest(request, env, url);
    }
    
    // ============ TOKEN GENERATION ENDPOINT ============
    if (url.pathname === '/api/auth/token') {
      return handleTokenRequest(request, env, ctx);
    }
    
    if (url.pathname === '/auth/callback') {
      return handleAuthCallback(request, env);
    }
    
    if (url.pathname === '/auth/logout') {
      return handleLogout();
    }

    // ============ ADMIN ENDPOINTS ============
    if (url.pathname.startsWith('/admin/') && env.ADMIN_TOKEN) {
      return handleAdminRequest(request, env, url);
    }
    
    // ============ CONFIGURATION VALIDATION ============
    const config = validateConfiguration(env);
    if (config.error) {
      return errorResponse(500, config.error);
    }
    
    // ============ EMERGENCY BYPASS ============
    if (config.authEnabled === false) {
      console.warn('🚨 AUTH DISABLED - Emergency bypass active');
      await logSecurityEvent('auth_bypass', request, env, { reason: 'emergency_mode' });
      return forwardToOrigin(request, config.tunnelUrl, {
        'X-CDN-Auth-Status': 'disabled',
        'X-CDN-Bypass-Reason': 'emergency'
      });
    }
    
    // ============ AUTHENTICATION FLOW ============
    let authResult = { valid: false, method: 'none' };
    
    // METHOD 1: BEARER TOKEN FROM HEADER
    const authHeader = request.headers.get('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      authResult = await validateBearerToken(token, env, config);
    }
    
    // METHOD 2: TOKEN FROM COOKIE
    if (!authResult.valid) {
      const cookieToken = getCookieValue(request, 'cdn_auth_token');
      if (cookieToken) {
        console.log('🔍 Checking cookie token...');
        authResult = await validateBearerToken(cookieToken, env, config);
        if (authResult.valid) {
          authResult.method = 'cookie_token';
        }
      }
    }
    
    // METHOD 3: HMAC SIGNATURE (API/Service clients)
    if (!authResult.valid) {
      authResult = await validateHMACAuth(request, config);
    }

    // ============ AUTHENTICATION FAILURE ============
    if (!authResult.valid) {
      await logAuthFailure(request, authResult, env);
      
      // Adaptive response based on request type
      return generateAuthFailureResponse(request, authResult);
    }
    
    // ============ AUTHENTICATION SUCCESS ============
    await logAuthSuccess(request, authResult, env);
    
    // ============ RATE LIMITING (Without KV - using memory cache alternative) ============
    if (authResult.clientId) {
      const rateLimitResult = await enforceRateLimitWithoutKV(authResult.clientId, clientIp, env);
      if (rateLimitResult.blocked) {
        await logSecurityEvent('rate_limit_exceeded', request, env, rateLimitResult);
        return rateLimitResponse(rateLimitResult);
      }
    }
    
    // ============ REQUEST FORWARDING ============
    const processingTime = Date.now() - startTime;
    return forwardAuthenticatedRequest(request, config.tunnelUrl, authResult, {
      clientIp,
      userAgent,
      processingTime
    });
  }
};

// ============ SECURITY ENHANCEMENTS ============

function performSecurityChecks(request, env) {
  const checks = {
    blocked: false,
    reasons: [],
    scores: {}
  };
  
  // 1. Cloudflare Threat Intelligence
  const threatScore = request.cf?.threat_score || 0;
  const botScore = request.cf?.botManagement?.score || 0;
  
  checks.scores.threat = threatScore;
  checks.scores.bot = botScore;
  
  if (threatScore > 25) {
    checks.blocked = true;
    checks.reasons.push(`high_threat_score:${threatScore}`);
  }
  
  if (env.BOT_PROTECTION_ENABLED === "true" && botScore > 85) {
    checks.blocked = true;
    checks.reasons.push(`confirmed_bot:${botScore}`);
  }
  
  // 2. Geographic Restrictions (Example)
  const country = request.cf?.country;
  const blockedCountries = env.BLOCKED_COUNTRIES ? JSON.parse(env.BLOCKED_COUNTRIES) : [];
  if (country && blockedCountries.includes(country)) {
    checks.blocked = true;
    checks.reasons.push(`country_blocked:${country}`);
  }
  
  // 3. Request Pattern Analysis
  const userAgent = request.headers.get('User-Agent') || '';
  const path = new URL(request.url).pathname;
  
  // Known malicious patterns
  const maliciousPatterns = [
    { pattern: /(\/\.\.\/|\.\.\/)/, type: 'path_traversal' },
    { pattern: /(%27|'|%22|")(\s*)(--|#|\/\*)/i, type: 'sql_injection' },
    { pattern: /<script|<iframe|javascript:/i, type: 'xss_attempt' }
  ];
  
  for (const { pattern, type } of maliciousPatterns) {
    if (pattern.test(path) || pattern.test(userAgent)) {
      checks.blocked = true;
      checks.reasons.push(type);
      break;
    }
  }
  
  // 4. Request Frequency (Basic - without KV, limited functionality)
  checks.scores.frequency = 'monitoring_disabled_no_kv';
  
  return checks;
}

function securityBlockResponse(check) {
  return new Response(JSON.stringify({
    error: 'Access denied',
    reason: 'Security policy violation',
    timestamp: new Date().toISOString(),
    request_id: generateRequestId()
  }), {
    status: 403,
    headers: {
      'Content-Type': 'application/json',
      'X-Security-Block': check.reasons.join(',')
    }
  });
}

// ============ TOKEN MANAGEMENT ============

async function handleTokenRequest(request, env, ctx) {
  // Security: Validate request method and headers
  if (request.method !== 'POST') {
    return errorResponse(405, 'Method not allowed', {
      'Allow': 'POST'
    });
  }
  
  // Security: Check content type
  const contentType = request.headers.get('Content-Type') || '';
  if (!contentType.includes('application/json')) {
    return errorResponse(415, 'Unsupported Media Type', {
      'Accept': 'application/json'
    });
  }
  
  // Rate limiting without KV - using simplified IP-based memory approach
  const clientIp = request.headers.get('CF-Connecting-IP');
  
  try {
    // Parse request body
    let body;
    try {
      const requestText = await request.text();
      console.log('📝 Request body received:', requestText.substring(0, 100) + '...');
      body = JSON.parse(requestText);
    } catch (parseError) {
      console.error('❌ JSON parse error:', parseError.message);
      return errorResponse(400, 'Invalid JSON format in request body');
    }
    
    const { clientId, clientSecret } = body;
    
    // Validate required fields
    if (!clientId || !clientSecret) {
      console.log('❌ Missing fields:', { clientId: !!clientId, clientSecret: !!clientSecret });
      return errorResponse(400, 'Missing required fields: clientId and clientSecret');
    }
    
    // Validate credentials
    console.log(`🔐 Token request from: ${clientId}, IP: ${clientIp}`);
    const isValid = await validateClientCredentials(clientId, clientSecret, env);
    
    if (!isValid) {
      await logSecurityEvent('token_request_failed', request, env, { 
        clientId, 
        ip: clientIp,
        reason: 'invalid_credentials'
      });
      return errorResponse(401, 'Invalid credentials');
    }
    
    // Generate secure token
    const token = await createSecureToken(clientId, env.SECRET_KEY, env, {
      ip: clientIp,
      userAgent: request.headers.get('User-Agent')
    });
    
    // Store token metadata (without KV, using in-memory approach)
    await storeTokenMetadataWithoutKV(token, env, {
      clientIp,
      userAgent: request.headers.get('User-Agent'),
      requestId: generateRequestId()
    });
    
    await logSecurityEvent('token_issued', request, env, { 
      clientId,
      tokenId: token.id,
      issuedAt: token.issued
    });
    
    // Return token with security headers
    return new Response(JSON.stringify({
      access_token: token.encoded,
      token_type: 'Bearer',
      expires_in: 3600,
      issued_at: token.issued,
      token_id: token.id
    }), {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        'Pragma': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY'
      }
    });
    
  } catch (error) {
    console.error('❌ Token request processing error:', error);
    return errorResponse(400, 'Invalid request format: ' + error.message);
  }
}

// ============ SIMPLE TOKEN CREATION ============

async function createSecureToken(clientId, secretKey, env, metadata = {}) {
  const issued = Date.now();
  const expires = issued + 3600000; // 1 hour
  const tokenId = generateSecureId();
  
  // Simple payload
  const payload = {
    id: tokenId,
    cid: clientId,
    iat: issued,
    exp: expires,
    ver: '1.0'
  };
  
  // Create signature
  const signature = await generateHMAC(JSON.stringify(payload), secretKey);
  payload.sig = signature;
  
  // Store token in memory if no KV (limited functionality)
  storeTokenInMemory(payload.id, {
    clientId,
    issued: payload.iat,
    expires: payload.exp,
    ip: metadata.clientIp,
    status: 'active'
  });
  
  return {
    id: tokenId,
    clientId,
    issued,
    expires,
    encoded: btoa(JSON.stringify(payload))
  };
}

// ============ SIMPLE IN-MEMORY TOKEN STORAGE ============

// Simple in-memory cache for tokens (limited by Worker memory constraints)
const tokenMemoryCache = new Map();
const CACHE_CLEANUP_INTERVAL = 3600000; // 1 hour

function storeTokenInMemory(tokenId, tokenData) {
  // Clean old entries periodically
  if (Math.random() < 0.01) { // 1% chance per token to clean up
    cleanupMemoryCache();
  }
  
  tokenMemoryCache.set(tokenId, {
    ...tokenData,
    storedAt: Date.now()
  });
}

function getTokenFromMemory(tokenId) {
  const token = tokenMemoryCache.get(tokenId);
  if (!token) return null;
  
  // Check if expired
  if (Date.now() > token.expires) {
    tokenMemoryCache.delete(tokenId);
    return null;
  }
  
  return token;
}

function cleanupMemoryCache() {
  const now = Date.now();
  for (const [tokenId, token] of tokenMemoryCache.entries()) {
    if (now > token.expires || (now - token.storedAt) > CACHE_CLEANUP_INTERVAL) {
      tokenMemoryCache.delete(tokenId);
    }
  }
}

// ============ TOKEN VALIDATION ============

async function validateBearerToken(token, env) {
  console.log('🔍 Token validation started');
  
  try {
    // Decode token
    const tokenData = JSON.parse(atob(token));
    
    // Check required fields
    if (!tokenData.id || !tokenData.cid || !tokenData.iat || !tokenData.exp || !tokenData.sig) {
      return { valid: false, reason: 'token_invalid_structure' };
    }
    
    // Check expiry
    if (Date.now() > tokenData.exp) {
      return { valid: false, reason: 'token_expired' };
    }
    
    // Extract and verify signature
    const signature = tokenData.sig;
    delete tokenData.sig; // Remove for verification
    
    // Recreate expected signature
    const expectedSig = await generateHMAC(JSON.stringify(tokenData), env.SECRET_KEY);
    
    if (!constantTimeCompare(signature, expectedSig)) {
      return { valid: false, reason: 'invalid_token_signature' };
    }
    
    // Check memory cache for revocation (limited without KV)
    const stored = getTokenFromMemory(tokenData.id);
    if (!stored) {
      // Without KV, we can't fully track token revocation
      // Token is considered valid based on signature and expiry only
      console.log('⚠️ Token not in memory cache - validation limited without KV');
    }
    
    return {
      valid: true,
      clientId: tokenData.cid,
      method: 'bearer_token',
      tokenId: tokenData.id
    };
    
  } catch (error) {
    console.error('❌ Token validation error:', error.message);
    return { valid: false, reason: 'token_parse_error' };
  }
}

// ============ STORE TOKEN METADATA (Without KV) ============

async function storeTokenMetadataWithoutKV(token, env, metadata) {
  // Store in memory cache only
  storeTokenInMemory(token.id, {
    id: token.id,
    clientId: token.clientId,
    issued: token.issued,
    expires: token.expires,
    ip: metadata.clientIp,
    userAgent: metadata.userAgent?.substring(0, 200) || 'unknown',
    requestId: metadata.requestId,
    status: 'active'
  });
}

// ============ ENHANCED HMAC AUTHENTICATION (Without KV nonce checking) ============

async function validateHMACAuth(request, config) {
  console.log('🔐 HMAC validation started');
  
  const clientId = request.headers.get('X-Client-Key');
  const signature = request.headers.get('X-Signature');
  const timestamp = request.headers.get('X-Timestamp');
  const nonce = request.headers.get('X-Nonce');
  const requestId = request.headers.get('X-Request-ID') || generateRequestId();
  
  // 1. Validate all required headers exist
  if (!clientId || !signature || !timestamp || !nonce) {
    console.log('❌ Missing HMAC headers');
    return { valid: false, reason: 'missing_headers' };
  }
  
  // 2. Validate client ID
  if (!config.allowedClients.includes(clientId)) {
    console.log(`❌ Client not allowed: ${clientId}`);
    return { valid: false, reason: 'invalid_client', clientId };
  }
  
  // 3. Validate timestamp
  const requestTime = parseInt(timestamp);
  if (isNaN(requestTime)) {
    console.log('❌ Invalid timestamp format');
    return { valid: false, reason: 'invalid_timestamp' };
  }
  
  const timeDiff = Math.abs(Date.now() - requestTime);
  const maxTimeDiff = (config.signatureTTL || 300) * 1000;
  
  if (timeDiff > maxTimeDiff) {
    console.log(`❌ Timestamp expired: diff ${timeDiff}ms, max ${maxTimeDiff}ms`);
    return { valid: false, reason: 'timestamp_expired' };
  }
  
  // 4. Nonce replay checking disabled without KV
  console.log('⚠️ Nonce replay checking disabled (KV required)');
  
  // 5. Generate expected signature
  const url = new URL(request.url);
  const pathWithQuery = url.pathname + url.search;
  const dataToSign = `${request.method}:${pathWithQuery}:${timestamp}:${nonce}:${requestId}`;
  const expectedSignature = await generateHMAC(dataToSign, config.secretKey);
  
  // 6. Constant-time comparison
  if (!constantTimeCompare(signature, expectedSignature)) {
    console.log('❌ Signature mismatch');
    await logSecurityEvent('hmac_signature_mismatch', request, config.env, { 
      clientId, 
      expected: expectedSignature.substring(0, 8),
      received: signature.substring(0, 8)
    });
    return { valid: false, reason: 'invalid_signature' };
  }
  
  console.log(`✅ HMAC validated for: ${clientId}`);
  
  return {
    valid: true,
    clientId,
    method: 'hmac_sha256',
    timestamp: requestTime,
    nonce,
    requestId
  };
}

// ============ ENHANCED CREDENTIAL VALIDATION ============

async function validateClientCredentials(clientId, clientSecret, env) {
  console.log(`🔐 Credential validation for: ${clientId}`);
  
  // 1. Parse and validate ALLOWED_CLIENTS
  const allowedClients = parseClientListRobust(env.ALLOWED_CLIENTS);
  if (!Array.isArray(allowedClients)) {
    console.error('❌ ALLOWED_CLIENTS configuration error');
    return false;
  }
  
  if (!allowedClients.includes(clientId)) {
    console.log(`❌ Client not in allowed list: ${clientId}`);
    return false;
  }
  
  console.log(`✅ Client ${clientId} is allowed`);
  
  // 2. Parse CLIENT_SECRETS with multiple strategies
  if (!env.CLIENT_SECRETS) {
    console.log('❌ CLIENT_SECRETS not configured');
    return false;
  }
  
  const clientSecrets = parseJSONRobust(env.CLIENT_SECRETS);
  if (!clientSecrets || typeof clientSecrets !== 'object') {
    console.error('❌ Failed to parse CLIENT_SECRETS');
    return false;
  }
  
  const expectedSecret = clientSecrets[clientId];
  if (!expectedSecret) {
    console.log(`❌ No secret found for client: ${clientId}`);
    return false;
  }
  
  // 3. Enhanced validation with additional checks
  if (typeof expectedSecret !== 'string' || expectedSecret.length < 8) {
    console.error(`❌ Invalid secret format for client: ${clientId}`);
    return false;
  }
  
  if (typeof clientSecret !== 'string') {
    console.log(`❌ Invalid client secret type for: ${clientId}`);
    return false;
  }
  
  // 4. Constant-time comparison
  const isValid = constantTimeCompare(clientSecret, expectedSecret);
  
  if (isValid) {
    console.log(`✅ Credentials valid for: ${clientId}`);
  } else {
    console.log(`❌ Credentials invalid for: ${clientId}`);
    // Without KV, we can't track failed attempts persistently
  }
  
  return isValid;
}

// ============ RATE LIMITING WITHOUT KV ============

// Simple in-memory rate limiting (works per Worker instance)
const rateLimitCache = new Map();

async function enforceRateLimitWithoutKV(clientId, clientIp, env) {
  const window = parseInt(env.RATE_LIMIT_WINDOW || "60");
  const limit = parseInt(env.RATE_LIMIT_MAX || "100");
  
  if (!limit || limit <= 0) {
    return { blocked: false };
  }
  
  const now = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(now / window) * window;
  
  // Clean old entries periodically
  if (Math.random() < 0.01) { // 1% chance per check to clean up
    cleanupRateLimitCache(window);
  }
  
  // Rate limit by client
  const clientKey = `client:${clientId}:${windowStart}`;
  const clientCount = getRateLimitCount(clientKey);
  
  // Rate limit by IP
  const ipKey = `ip:${clientIp}:${windowStart}`;
  const ipCount = getRateLimitCount(ipKey);
  
  if (clientCount >= limit || ipCount >= (limit * 2)) {
    const resetTime = windowStart + window;
    return {
      blocked: true,
      reason: clientCount >= limit ? 'client_limit' : 'ip_limit',
      limit,
      clientCount,
      ipCount,
      retryAfter: resetTime - now,
      resetTime
    };
  }
  
  // Increment counters
  incrementRateLimit(clientKey, window * 2);
  incrementRateLimit(ipKey, window * 2);
  
  return {
    blocked: false,
    limit,
    clientRemaining: limit - (clientCount + 1),
    ipRemaining: (limit * 2) - (ipCount + 1),
    resetTime: windowStart + window
  };
}

function getRateLimitCount(key) {
  const entry = rateLimitCache.get(key);
  if (!entry || Date.now() > entry.expires) {
    return 0;
  }
  return entry.count || 0;
}

function incrementRateLimit(key, ttl) {
  const current = getRateLimitCount(key);
  rateLimitCache.set(key, {
    count: current + 1,
    expires: Date.now() + (ttl * 1000)
  });
}

function cleanupRateLimitCache(currentWindow) {
  const now = Date.now();
  for (const [key, entry] of rateLimitCache.entries()) {
    if (now > entry.expires) {
      rateLimitCache.delete(key);
    }
  }
}

// ============ ENHANCED FORWARDING & RESPONSE ============

async function forwardAuthenticatedRequest(request, tunnelUrl, authResult, metadata = {}) {
  const url = new URL(request.url);
  const targetUrl = new URL(tunnelUrl);
  targetUrl.pathname = url.pathname;
  targetUrl.search = url.search;
  
  const headers = new Headers(request.headers);
  
  // Clean all client authentication headers
  const headersToRemove = [
    'X-Client-Key', 'X-Signature', 'X-Timestamp', 'X-Nonce',
    'Authorization', 'X-API-Key', 'X-Auth-Token'
  ];
  
  headersToRemove.forEach(h => headers.delete(h));
  
  // Add security verification headers
  headers.set('X-CDN-Verified', 'true');
  headers.set('X-CDN-Client-ID', authResult.clientId);
  headers.set('X-CDN-Auth-Method', authResult.method);
  headers.set('X-CDN-Auth-Time', Date.now().toString());
  headers.set('X-CDN-Request-ID', generateRequestId());
  
  // Add tracing headers
  headers.set('X-Original-IP', metadata.clientIp || 'unknown');
  headers.set('X-Forwarded-For', metadata.clientIp || 'unknown');
  headers.set('X-Forwarded-Host', url.hostname);
  headers.set('X-Forwarded-Proto', 'https');
  headers.set('X-Request-Processing-Time', metadata.processingTime?.toString() || '0');
  
  // Add security headers
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  if (authResult.tokenId) {
    headers.set('X-CDN-Token-ID', authResult.tokenId);
  }
  
  if (authResult.requestId) {
    headers.set('X-CDN-Request-ID', authResult.requestId);
  }
  
  try {
    console.log(`🌐 Forwarding to origin: ${targetUrl.toString()}`);
    
    const fetchOptions = {
      method: request.method,
      headers: headers,
      body: request.body,
      redirect: 'manual',
      cf: {
        cacheTtl: 0,
        cacheEverything: false,
        polish: 'off'
      }
    };
    
    const response = await fetch(targetUrl.toString(), fetchOptions);
    
    // Create new response with security headers
    const responseHeaders = new Headers(response.headers);
    
    // Ensure security headers are present
    if (!responseHeaders.has('X-Content-Type-Options')) {
      responseHeaders.set('X-Content-Type-Options', 'nosniff');
    }
    
    if (!responseHeaders.has('X-Frame-Options')) {
      responseHeaders.set('X-Frame-Options', 'DENY');
    }
    
    // Add CDN response headers
    responseHeaders.set('X-CDN-Processed', 'true');
    responseHeaders.set('X-CDN-Client', authResult.clientId);
    
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
    
  } catch (error) {
    console.error('❌ Origin fetch error:', error);
    await logSecurityEvent('origin_unavailable', request, { tunnelUrl }, { 
      error: error.message,
      clientId: authResult.clientId
    });
    
    return errorResponse(502, 'Origin server unavailable', {
      'Retry-After': '30',
      'X-Origin-Status': 'unavailable'
    });
  }
}

// ============ PUBLIC REQUEST HANDLING ============

function handlePublicRequest(request, env, url) {
  console.log(`🌐 Public endpoint: ${url.pathname}`);
  
  if (url.pathname === '/health') {
    return new Response(JSON.stringify({
      status: 'healthy',
      worker: 'cdn-auth',
      version: 'production-v2.0',
      timestamp: new Date().toISOString(),
      uptime: 'running',
      region: request.cf?.colo || 'unknown',
      kv_enabled: !!env.AUTH_STORE,
      kv_status: env.AUTH_STORE ? 'connected' : 'not_configured'
    }), {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=30',
        'X-Health-Check': 'true'
      }
    });
  }
  
  if (url.pathname === '/status') {
    return new Response(JSON.stringify({
      status: 'operational',
      components: {
        authentication: 'enabled',
        rate_limiting: env.RATE_LIMIT_MAX ? 'enabled' : 'disabled',
        bot_protection: env.BOT_PROTECTION_ENABLED === "true" ? 'enabled' : 'disabled',
        kv_store: env.AUTH_STORE ? 'connected' : 'not_configured',
        kv_features: env.AUTH_STORE ? 'full' : 'limited',
        memory_cache: 'enabled'
      },
      limitations: env.AUTH_STORE ? [] : ['nonce_replay_protection_disabled', 'persistent_token_revocation_disabled'],
      timestamp: new Date().toISOString()
    }), {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=10'
      }
    });
  }
  
  if (url.pathname === '/robots.txt') {
    return new Response('User-agent: *\nDisallow: /\nAllow: /health\nAllow: /status\n', {
      headers: {
        'Content-Type': 'text/plain',
        'Cache-Control': 'public, max-age=3600'
      }
    });
  }
  
  // Default for any other public path
  return errorResponse(404, 'Not found');
}

// ============ ADMIN REQUEST HANDLING (Adapted for no KV) ============

async function handleAdminRequest(request, env, url) {
  const adminToken = request.headers.get('X-Admin-Token');
  
  // Verify admin token
  if (!adminToken || adminToken !== env.ADMIN_TOKEN) {
    await logSecurityEvent('admin_unauthorized', request, env, {
      path: url.pathname,
      ip: request.headers.get('CF-Connecting-IP')
    });
    return errorResponse(403, 'Forbidden');
  }
  
  // Admin endpoints
  if (url.pathname === '/admin/stats') {
    return await getAdminStats(request, env);
  }
  
  if (url.pathname === '/admin/clients') {
    return await manageClients(request, env);
  }
  
  if (url.pathname === '/admin/tokens') {
    return await manageTokensWithoutKV(request, env);
  }
  
  return errorResponse(404, 'Admin endpoint not found');
}

async function getAdminStats(request, env) {
  const stats = {
    timestamp: new Date().toISOString(),
    worker: {
      name: 'cdn-auth-production',
      version: '2.0',
      region: request.cf?.colo || 'unknown'
    },
    configuration: {
      auth_enabled: env.AUTH_ENABLED === "true",
      bot_protection: env.BOT_PROTECTION_ENABLED === "true",
      rate_limit_enabled: !!env.RATE_LIMIT_MAX,
      signature_ttl: parseInt(env.SIGNATURE_TTL || "300"),
      allowed_clients_count: parseClientList(env.ALLOWED_CLIENTS).length,
      has_secret_key: !!env.SECRET_KEY,
      has_client_secrets: !!env.CLIENT_SECRETS,
      kv_configured: !!env.AUTH_STORE
    },
    memory_cache: {
      token_count: tokenMemoryCache.size,
      rate_limit_entries: rateLimitCache.size,
      status: 'active'
    },
    security: {
      threat_score: request.cf?.threat_score || 0,
      bot_score: request.cf?.botManagement?.score || 0,
      country: request.cf?.country || 'unknown',
      asn: request.cf?.asn || 'unknown'
    }
  };
  
  return new Response(JSON.stringify(stats, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
  });
}

async function manageClients(request, env) {
  if (request.method === 'GET') {
    const allowedClients = parseClientList(env.ALLOWED_CLIENTS);
    const clientSecrets = parseJSONRobust(env.CLIENT_SECRETS) || {};
    
    const clients = allowedClients.map(clientId => ({
      id: clientId,
      has_secret: !!clientSecrets[clientId],
      secret_length: clientSecrets[clientId] ? clientSecrets[clientId].length : 0,
      status: 'active'
    }));
    
    return new Response(JSON.stringify({ clients }, null, 2), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  return errorResponse(405, 'Method not allowed', { 'Allow': 'GET' });
}

async function manageTokensWithoutKV(request, env) {
  if (request.method === 'GET') {
    const tokens = {
      note: 'KV store not configured. Using in-memory cache only.',
      limitations: [
        'Token revocation not persistent across Worker instances',
        'No historical token tracking',
        'Limited to current Worker instance memory'
      ],
      memory_cache: {
        token_count: tokenMemoryCache.size,
        active_tokens: Array.from(tokenMemoryCache.keys())
      }
    };
    
    return new Response(JSON.stringify(tokens, null, 2), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  if (request.method === 'DELETE') {
    try {
      const { tokenId } = await request.json();
      if (!tokenId) {
        return errorResponse(400, 'Missing tokenId');
      }
      
      // Remove from memory cache
      const removed = tokenMemoryCache.delete(tokenId);
      
      return new Response(JSON.stringify({
        success: true,
        removed_from_memory: removed,
        message: removed ? `Token ${tokenId} revoked from memory` : `Token ${tokenId} not found in memory`,
        note: 'Revocation not persistent without KV store',
        timestamp: new Date().toISOString()
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      return errorResponse(400, 'Invalid request');
    }
  }
  
  return errorResponse(405, 'Method not allowed', { 'Allow': 'GET, DELETE' });
}

// ============ ENHANCED LOGIN PAGE ============

function serveEnhancedLoginPage(request, authResult) {
  const requestId = generateRequestId();
  
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login | Secure Access</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            margin: 0;
        }
        
        .login-box {
            background: white;
            border-radius: 20px;
            padding: 40px;
            max-width: 400px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .logo-icon {
            font-size: 48px;
            color: #667eea;
            margin-bottom: 15px;
        }
        
        h1 {
            color: #1a202c;
            margin-bottom: 10px;
            text-align: center;
        }
        
        .subtitle {
            color: #718096;
            text-align: center;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #4a5568;
            font-weight: 500;
        }
        
        input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.2s;
        }
        
        input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .login-btn {
            width: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 14px;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .login-btn:hover {
            transform: translateY(-2px);
        }
        
        .login-btn:disabled {
            opacity: 0.7;
            cursor: not-allowed;
        }
        
        .status {
            margin-top: 20px;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            font-size: 14px;
            display: none;
        }
        
        .status.success {
            background: #c6f6d5;
            color: #22543d;
            border: 1px solid #9ae6b4;
            display: block;
        }
        
        .status.error {
            background: #fed7d7;
            color: #742a2a;
            border: 1px solid #fc8181;
            display: block;
        }
        
        .info {
            margin-top: 25px;
            padding-top: 25px;
            border-top: 1px solid #e2e8f0;
            text-align: center;
            color: #718096;
            font-size: 14px;
        }
        
        .debug {
            margin-top: 15px;
            padding: 10px;
            background: #f7fafc;
            border-radius: 8px;
            font-size: 12px;
            color: #4a5568;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">
            <div class="logo-icon">🔐</div>
            <h1>Secure Login</h1>
            <div class="subtitle">Enter your credentials to continue</div>
        </div>
        
        <div id="status" class="status"></div>
        
        <form id="loginForm" onsubmit="login(event)">
            <div class="form-group">
                <label for="clientId">Client ID</label>
                <input type="text" id="clientId" placeholder="Enter Client ID" value="web-client" required>
            </div>
            
            <div class="form-group">
                <label for="clientSecret">Client Secret</label>
                <input type="password" id="clientSecret" placeholder="Enter Client Secret" required>
            </div>
            
            <button type="submit" class="login-btn" id="loginBtn">
                <span id="btnText">Login</span>
                <span id="btnSpinner" style="display: none;">⏳</span>
            </button>
        </form>
        
        <div class="info">
            <p>Need credentials? Contact your administrator.</p>
        </div>
        
        <div class="debug">
            <div><strong>Request ID:</strong> ${requestId}</div>
            <div><strong>Status:</strong> ${authResult.reason || 'Not authenticated'}</div>
        </div>
    </div>
    
    <script>
        async function login(event) {
            event.preventDefault();
            
            const clientId = document.getElementById('clientId').value;
            const clientSecret = document.getElementById('clientSecret').value;
            const loginBtn = document.getElementById('loginBtn');
            const btnText = document.getElementById('btnText');
            const btnSpinner = document.getElementById('btnSpinner');
            const status = document.getElementById('status');
            
            // Show loading state
            loginBtn.disabled = true;
            btnText.textContent = 'Authenticating...';
            btnSpinner.style.display = 'inline';
            
            try {
                const response = await fetch('/api/auth/token', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        clientId: clientId,
                        clientSecret: clientSecret
                    })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    // Show success message
                    status.className = 'status success';
                    status.innerHTML = '✓ Authentication successful! Redirecting...';
                    
                    // Redirect to auth callback with token
                    setTimeout(() => {
                        window.location.href = '/auth/callback?token=' + encodeURIComponent(data.access_token);
                    }, 1000);
                    
                } else {
                    const error = await response.json();
                    throw new Error(error.error || 'Authentication failed');
                }
            } catch (error) {
                // Show error
                status.className = 'status error';
                status.innerHTML = '✗ ' + error.message;
                
                // Reset button
                loginBtn.disabled = false;
                btnText.textContent = 'Login';
                btnSpinner.style.display = 'none';
            }
        }
        
        // Auto-focus on password field
        document.addEventListener('DOMContentLoaded', function() {
            const clientSecret = document.getElementById('clientSecret');
            if (clientSecret.value === '') {
                clientSecret.focus();
            }
        });
    </script>
</body>
</html>`;
  
  return new Response(html, {
    status: 401,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'X-Request-ID': requestId
    }
  });
}

// ============ ENHANCED UTILITY FUNCTIONS ============

function generateSecureId() {
  const array = new Uint8Array(24);
  crypto.getRandomValues(array);
  return Array.from(array)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function generateRequestId() {
  return `req_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
}

// ============ LOGGING & MONITORING ============

async function logSecurityEvent(type, request, env, data = {}) {
  const logEntry = {
    id: generateRequestId(),
    type,
    timestamp: new Date().toISOString(),
    level: getLogLevel(type),
    source: 'cdn-auth-worker',
    ip: request?.headers?.get('CF-Connecting-IP') || 'internal',
    path: request ? new URL(request.url).pathname : 'internal',
    userAgent: request ? (request.headers.get('User-Agent') || '').substring(0, 200) : 'internal',
    country: request?.cf?.country,
    asn: request?.cf?.asn,
    colo: request?.cf?.colo,
    threatScore: request?.cf?.threat_score,
    botScore: request?.cf?.botManagement?.score,
    kv_enabled: !!env.AUTH_STORE,
    ...data
  };
  
  // Console logging with appropriate level
  const logMessage = `[${logEntry.level.toUpperCase()}] ${type}: ${JSON.stringify(logEntry)}`;
  if (logEntry.level === 'error' || logEntry.level === 'warning') {
    console.error(logMessage);
  } else {
    console.log(logMessage);
  }
  
  // Without KV, logs are only written to console
  // Consider using Workers Analytics or external logging service for production
}

function getLogLevel(eventType) {
  const errorEvents = ['auth_failure', 'security_block', 'token_signature_invalid', 'origin_unavailable'];
  const warningEvents = ['rate_limit_exceeded', 'nonce_reuse', 'bot_blocked'];
  
  if (errorEvents.includes(eventType)) return 'error';
  if (warningEvents.includes(eventType)) return 'warning';
  return 'info';
}

async function logAuthFailure(request, authResult, env) {
  await logSecurityEvent('auth_failure', request, env, {
    reason: authResult.reason,
    clientId: authResult.clientId || 'unknown',
    method: authResult.method,
    ip: request.headers.get('CF-Connecting-IP')
  });
}

async function logAuthSuccess(request, authResult, env) {
  await logSecurityEvent('auth_success', request, env, {
    clientId: authResult.clientId,
    method: authResult.method,
    tokenId: authResult.tokenId
  });
}

// ============ RESPONSE HELPERS ============

function errorResponse(status, message, headers = {}) {
  return new Response(JSON.stringify({
    error: message,
    timestamp: new Date().toISOString(),
    request_id: generateRequestId()
  }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      ...headers
    }
  });
}

function rateLimitResponse(limitResult) {
  return new Response(JSON.stringify({
    error: 'Rate limit exceeded',
    reason: limitResult.reason,
    limit: limitResult.limit,
    retry_after: limitResult.retryAfter,
    reset_time: new Date(limitResult.resetTime * 1000).toISOString(),
    timestamp: new Date().toISOString()
  }), {
    status: 429,
    headers: {
      'Content-Type': 'application/json',
      'Retry-After': limitResult.retryAfter.toString(),
      'X-RateLimit-Limit': limitResult.limit.toString(),
      'X-RateLimit-Remaining': '0',
      'X-RateLimit-Reset': limitResult.resetTime.toString()
    }
  });
}

function generateAuthFailureResponse(request, authResult) {
  const accept = request.headers.get('Accept') || '';
  const userAgent = request.headers.get('User-Agent') || '';
  
  if (accept.includes('text/html') || 
      userAgent.includes('Mozilla') || 
      userAgent.includes('Chrome') || 
      userAgent.includes('Safari')) {
    return serveEnhancedLoginPage(request, authResult);
  }
  
  // API response
  return errorResponse(401, 'Authentication required', {
    'WWW-Authenticate': `Bearer realm="API", error="${authResult.reason}"`,
    'X-Auth-Methods': 'Bearer, HMAC-SHA256',
    'X-Auth-Failure-Reason': authResult.reason
  });
}

// ============ CORE UTILITY FUNCTIONS ============

function validateConfiguration(env) {
  const secretKey = env.SECRET_KEY;
  const tunnelUrl = env.TUNNEL_URL;
  
  if (!secretKey || secretKey.length < 32) {
    return { error: "Invalid SECRET_KEY configuration" };
  }
  
  if (!tunnelUrl) {
    return { error: "Missing TUNNEL_URL configuration" };
  }
  
  return {
    secretKey,
    tunnelUrl,
    allowedClients: parseClientList(env.ALLOWED_CLIENTS),
    authEnabled: env.AUTH_ENABLED === "true",
    signatureTTL: parseInt(env.SIGNATURE_TTL || "300"),
    env: env
  };
}

function parseClientList(input) {
  if (!input) return [];
  if (Array.isArray(input)) return input;
  if (typeof input === 'string') {
    try {
      return JSON.parse(input);
    } catch {
      return input.split(',').map(s => s.trim()).filter(s => s);
    }
  }
  return [];
}

function parsePathList(input) {
  if (!input) return ['/health', '/status'];
  if (Array.isArray(input)) return input;
  if (typeof input === 'string') {
    try {
      return JSON.parse(input);
    } catch {
      return input.split(',').map(s => s.trim()).filter(s => s);
    }
  }
  return ['/health', '/status'];
}

function parseJSONRobust(input) {
  if (!input || typeof input !== 'string') {
    return input;
  }
  
  try {
    return JSON.parse(input);
  } catch (error) {
    console.error('JSON parse error:', error.message);
    return null;
  }
}

function parseClientListRobust(input) {
  const parsed = parseJSONRobust(input);
  if (Array.isArray(parsed)) {
    return parsed;
  }
  
  if (typeof input === 'string') {
    return input.split(',').map(s => s.trim()).filter(s => s);
  }
  
  return [];
}

function constantTimeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  
  const encoder = new TextEncoder();
  const aBuf = encoder.encode(a);
  const bBuf = encoder.encode(b);
  let result = 0;
  
  for (let i = 0; i < aBuf.length; i++) {
    result |= aBuf[i] ^ bBuf[i];
  }
  return result === 0;
}

async function generateHMAC(data, secretKey) {
  try {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secretKey);
    const msgData = encoder.encode(data);
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw', keyData, 
      { name: 'HMAC', hash: 'SHA-256' }, 
      false, 
      ['sign']
    );
    
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, msgData);
    return Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  } catch (error) {
    console.error('HMAC generation error:', error);
    throw new Error('Failed to generate HMAC');
  }
}

async function forwardToOrigin(request, tunnelUrl, extraHeaders = {}) {
  const url = new URL(request.url);
  const targetUrl = new URL(tunnelUrl);
  targetUrl.pathname = url.pathname;
  targetUrl.search = url.search;
  
  const headers = new Headers(request.headers);
  
  // Clean client auth headers
  ['X-Client-Key', 'X-Signature', 'X-Timestamp', 'X-Nonce', 'Authorization'].forEach(h => {
    headers.delete(h);
  });
  
  // Add verification headers
  Object.entries(extraHeaders).forEach(([key, value]) => {
    headers.set(key, value);
  });
  
  // Add security headers
  headers.set('X-Forwarded-Proto', 'https');
  headers.set('X-Forwarded-Host', url.hostname);
  
  try {
    const response = await fetch(targetUrl.toString(), {
      method: request.method,
      headers: headers,
      body: request.body,
      cf: {
        cacheTtl: 0,
        cacheEverything: false
      }
    });
    
    // Add security headers to response
    const newHeaders = new Headers(response.headers);
    newHeaders.set('X-Content-Type-Options', 'nosniff');
    newHeaders.set('X-Frame-Options', 'DENY');
    newHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    return new Response(response.body, {
      status: response.status,
      headers: newHeaders
    });
  } catch (error) {
    console.error('Origin fetch error:', error);
    return errorResponse(502, 'Origin server unavailable');
  }
}