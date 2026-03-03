// ============ COMPLETE WORKER WITH TOKEN VALIDATION ============
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // ============ DEBUG ENDPOINTS ============
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({
        status: 'healthy',
        version: 'cdn-auth-with-token-validation',
        timestamp: new Date().toISOString()
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    if (url.pathname === '/debug/vars') {
      let clientSecretsParsed = null;
      try {
        clientSecretsParsed = env.CLIENT_SECRETS ? JSON.parse(env.CLIENT_SECRETS) : null;
      } catch (e) {
        clientSecretsParsed = { error: e.message };
      }
      
      return new Response(JSON.stringify({
        CLIENT_SECRETS_EXISTS: !!env.CLIENT_SECRETS,
        CLIENT_SECRETS_PARSED: clientSecretsParsed,
        timestamp: new Date().toISOString()
      }, null, 2));
    }
    
    // ============ TOKEN VALIDATION DEBUG ============
    if (url.pathname === '/debug/token-check') {
      const authHeader = request.headers.get('Authorization');
      let tokenValid = false;
      let clientId = null;
      let decodedToken = null;
      
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        try {
          // Decode token (just for debugging)
          decodedToken = JSON.parse(atob(token));
          console.log('Decoded token:', decodedToken);
          
          // Validate token properly
          const result = await validateBearerToken(token, env);
          tokenValid = result.valid;
          clientId = result.clientId;
        } catch (error) {
          console.error('Token debug error:', error);
        }
      }
      
      return new Response(JSON.stringify({
        has_auth_header: !!authHeader,
        auth_header: authHeader ? authHeader.substring(0, 30) + '...' : null,
        token_valid: tokenValid,
        client_id: clientId,
        decoded_token: decodedToken,
        timestamp: new Date().toISOString()
      }, null, 2));
    }
    
    // ============ TOKEN GENERATION ENDPOINT ============
    if (url.pathname === '/api/auth/token') {
      return handleTokenRequest(request, env);
    }
    
    // ============ MAIN REQUEST FLOW WITH TOKEN VALIDATION ============
    let authResult = { valid: false };
    
    // 1. FIRST: Check for Bearer Token
    const authHeader = request.headers.get('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      console.log('🔐 Checking Bearer token...');
      authResult = await validateBearerToken(token, env);
    }
    
    // 2. SECOND: If no valid token, check HMAC headers
    if (!authResult.valid) {
      console.log('🔐 No valid token, checking HMAC...');
      authResult = await validateHMACAuth(request, {
        secretKey: env.SECRET_KEY,
        allowedClients: parseClientList(env.ALLOWED_CLIENTS),
        signatureTTL: parseInt(env.SIGNATURE_TTL || "300"),
        kvStore: env.AUTH_STORE
      });
    }
    
    // ============ AUTHENTICATION FAILED ============
    if (!authResult.valid) {
      console.log('❌ Authentication failed:', authResult.reason);
      return new Response('Authentication required', { status: 401 });
    }
    
    // ============ AUTHENTICATION SUCCESS ============
    console.log('✅ Authentication successful for:', authResult.clientId);
    
    // Forward to origin with verification headers
    return forwardToOrigin(request, env, authResult);
  }
};

// ============ BEARER TOKEN VALIDATION ============
async function validateBearerToken(token, env) {
  console.log('🔍 Validating Bearer token...');
  
  try {
    // Decode token
    const tokenData = JSON.parse(atob(token));
    console.log('Token data:', tokenData);
    
    // Check expiry
    if (Date.now() > tokenData.exp) {
      console.log('❌ Token expired');
      return { valid: false, reason: 'token_expired' };
    }
    
    // Extract and verify signature
    const signature = tokenData.sig;
    delete tokenData.sig; // Remove for verification
    
    // Recreate expected signature
    const expectedSig = await generateHMAC(
      JSON.stringify(tokenData), 
      env.SECRET_KEY
    );
    
    if (!constantTimeCompare(signature, expectedSig)) {
      console.log('❌ Token signature invalid');
      console.log('Expected:', expectedSig.substring(0, 10) + '...');
      console.log('Got:', signature.substring(0, 10) + '...');
      return { valid: false, reason: 'invalid_token_signature' };
    }
    
    console.log('✅ Token signature valid');
    
    // Optional: Check KV for revocation
    if (env.AUTH_STORE) {
      const stored = await env.AUTH_STORE.get(`token:${tokenData.id}`);
      if (!stored) {
        console.log('❌ Token not found in KV (revoked or expired)');
        return { valid: false, reason: 'token_revoked' };
      }
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

// ============ TOKEN GENERATION ============
async function handleTokenRequest(request, env) {
  console.log('🔑 TOKEN REQUEST');
  
  if (request.method !== 'POST') {
    return errorResponse(405, 'Method not allowed');
  }
  
  try {
    const body = await request.json();
    const { clientId, clientSecret } = body;
    
    if (!clientId || !clientSecret) {
      return errorResponse(400, 'Missing clientId or clientSecret');
    }
    
    // Validate credentials
    const isValid = await validateClientCredentials(clientId, clientSecret, env);
    console.log('Credential validation:', isValid);
    
    if (!isValid) {
      return errorResponse(401, 'Invalid credentials');
    }
    
    // Create signed token
    const token = await createSignedToken(clientId, env.SECRET_KEY, env);
    
    return new Response(JSON.stringify({
      access_token: token.encoded,
      token_type: 'Bearer',
      expires_in: 3600,
      client_id: clientId
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Token request error:', error);
    return errorResponse(400, 'Invalid request');
  }
}

// ============ ORIGIN FORWARDING ============
async function forwardToOrigin(request, env, authResult) {
  const url = new URL(request.url);
  const targetUrl = new URL(env.TUNNEL_URL);
  targetUrl.pathname = url.pathname;
  targetUrl.search = url.search;
  
  const headers = new Headers(request.headers);
  
  // Clean client auth headers
  ['X-Client-Key', 'X-Signature', 'X-Timestamp', 'X-Nonce', 'Authorization'].forEach(h => {
    headers.delete(h);
  });
  
  // Add verification headers
  headers.set('X-CDN-Verified', 'true');
  headers.set('X-CDN-Client-ID', authResult.clientId);
  headers.set('X-CDN-Auth-Method', authResult.method);
  headers.set('X-CDN-Auth-Time', Date.now().toString());
  headers.set('X-Forwarded-Host', url.hostname);
  headers.set('X-Original-IP', request.headers.get('CF-Connecting-IP') || 'unknown');
  
  try {
    console.log('🌐 Forwarding to origin:', targetUrl.toString());
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
    console.error('❌ Origin fetch error:', error);
    return new Response('Origin server unavailable', { status: 502 });
  }
}

// ============ SINGLE VALIDATE FUNCTION (NO DUPLICATES) ============
async function validateClientCredentials(clientId, clientSecret, env) {
  console.log('🔐 === CREDENTIAL VALIDATION START ===');
  console.log('Client ID:', clientId);
  console.log('Client Secret provided (length):', clientSecret?.length);
  
  // 1. Parse ALLOWED_CLIENTS with robust parsing
  const allowedClients = parseClientListRobust(env.ALLOWED_CLIENTS);
  console.log('Allowed clients parsed:', allowedClients);
  
  if (!Array.isArray(allowedClients)) {
    console.error('❌ ALLOWED_CLIENTS is not an array:', allowedClients);
    return false;
  }
  
  if (!allowedClients.includes(clientId)) 	{
    console.log('❌ Client not in allowed list');
    return false;
  }
  
  console.log('✅ Client ID is allowed');
  
  // 2. Robust CLIENT_SECRETS parsing
  if (!env.CLIENT_SECRETS) {
    console.log('❌ CLIENT_SECRETS not set');
    return false;
  }
  
  console.log('CLIENT_SECRETS raw (first 100 chars):', env.CLIENT_SECRETS.substring(0, 100));
  
  const clientSecrets = parseJSONRobust(env.CLIENT_SECRETS);
  if (!clientSecrets || typeof clientSecrets !== 'object') {
    console.error('❌ Failed to parse CLIENT_SECRETS as object');
    console.error('Parsed result:', clientSecrets);
    return false;
  }
  
  console.log('✅ CLIENT_SECRETS parsed successfully');
  console.log('Available client IDs:', Object.keys(clientSecrets));
  
  const expectedSecret = clientSecrets[clientId];
  if (!expectedSecret) {
    console.log(`❌ Client ID "${clientId}" not found in CLIENT_SECRETS`);
    return false;
  }
  
  console.log('Expected secret type:', typeof expectedSecret);
  console.log('Expected secret length:', expectedSecret.length);
  console.log('Provided secret length:', clientSecret.length);
  
  // 3. Debug string comparison
  console.log('=== STRING COMPARISON DEBUG ===');
  
  // Check for invisible characters
  const expectedClean = expectedSecret.replace(/[^\x20-\x7E]/g, '?');
  const providedClean = clientSecret.replace(/[^\x20-\x7E]/g, '?');
  
  console.log('Expected (clean):', JSON.stringify(expectedClean));
  console.log('Provided (clean):', JSON.stringify(providedClean));
  console.log('Exact match?', expectedSecret === clientSecret);
  
  // Character-by-character comparison
  if (expectedSecret.length !== clientSecret.length) {
    console.log(`❌ Length mismatch: expected ${expectedSecret.length}, got ${clientSecret.length}`);
    console.log('Expected chars:', Array.from(expectedSecret).map(c => `${c}(${c.charCodeAt(0)})`));
    console.log('Provided chars:', Array.from(clientSecret).map(c => `${c}(${c.charCodeAt(0)})`));
    return false;
  }
  
  // Final comparison
  const isValid = constantTimeCompare(clientSecret, expectedSecret);
  console.log('✅ constantTimeCompare result:', isValid);
  
  return isValid;
}

// ============ ROBUST PARSING FUNCTIONS ============
function parseJSONRobust(input) {
  if (!input || typeof input !== 'string') {
    return input; // Return as-is if not a string
  }
  
  const strategies = [
    // Strategy 1: Direct JSON parse
    (str) => {
      try {
        return JSON.parse(str);
      } catch (e) {
        throw new Error(`Direct parse failed: ${e.message}`);
      }
    },
    
    // Strategy 2: Remove whitespace and parse
    (str) => {
      try {
        const cleaned = str
          .replace(/\s+/g, ' ')
          .replace(/^\s+|\s+$/g, '')
          .replace(/,(\s*[}\]])/g, '$1'); // Remove trailing commas
        return JSON.parse(cleaned);
      } catch (e) {
        throw new Error(`Cleaned parse failed: ${e.message}`);
      }
    },
    
    // Strategy 3: Fix common JSON issues
    (str) => {
      try {
        let fixed = str;
        
        // Replace smart quotes with straight quotes
        fixed = fixed.replace(/[“”]/g, '"');
        
        // Fix single quotes to double quotes (carefully)
        fixed = fixed.replace(/([{,]\s*)'([^']+)'(\s*[:}])/g, '$1"$2"$3');
        
        // Add missing quotes around property names
        fixed = fixed.replace(/([{,]\s*)(\w+)(\s*:)/g, '$1"$2"$3');
        
        return JSON.parse(fixed);
      } catch (e) {
        throw new Error(`Fixed parse failed: ${e.message}`);
      }
    },
    
    // Strategy 4: Extract JSON object from malformed string
    (str) => {
      try {
        // Find first { and last }
        const start = str.indexOf('{');
        const end = str.lastIndexOf('}');
        
        if (start === -1 || end === -1 || end <= start) {
          throw new Error('No JSON object found');
        }
        
        const jsonStr = str.substring(start, end + 1);
        return JSON.parse(jsonStr);
      } catch (e) {
        throw new Error(`Extract parse failed: ${e.message}`);
      }
    }
  ];
  
  for (const strategy of strategies) {
    try {
      const result = strategy(input);
      console.log(`✅ JSON parse successful with strategy ${strategies.indexOf(strategy) + 1}`);
      return result;
    } catch (error) {
      console.log(`Strategy ${strategies.indexOf(strategy) + 1} failed:`, error.message);
      continue;
    }
  }
  
  console.error('❌ All JSON parsing strategies failed');
  console.error('Input was:', input);
  return null;
}

function parseClientListRobust(input) {
  if (!input) return [];
  if (Array.isArray(input)) return input;
  
  // Try parsing as JSON first
  const jsonParsed = parseJSONRobust(input);
  if (Array.isArray(jsonParsed)) {
    return jsonParsed;
  }
  
  // Fallback to comma-separated
  if (typeof input === 'string') {
    return input.split(',')
      .map(s => s.trim())
      .filter(s => s.length > 0);
  }
  
  return [];
}

function constantTimeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    console.log('❌ constantTimeCompare: inputs not strings', typeof a, typeof b);
    return false;
  }
  
  if (a.length !== b.length) {
    console.log(`❌ Length mismatch: ${a.length} vs ${b.length}`);
    return false;
  }
  
  const encoder = new TextEncoder();
  let aBuf, bBuf;
  
  try {
    aBuf = encoder.encode(a);
    bBuf = encoder.encode(b);
  } catch (error) {
    console.error('TextEncoder error:', error);
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < aBuf.length; i++) {
    result |= aBuf[i] ^ bBuf[i];
  }
  
  return result === 0;
}

async function createSignedToken(clientId, secretKey, env) {
  const payload = {
    id: generateRandomId(),
    cid: clientId,
    iat: Date.now(),
    exp: Date.now() + 3600000,
    ver: 'v1'
  };
  
  const signature = await generateHMAC(JSON.stringify(payload), secretKey);
  payload.sig = signature;
  
  // Store token in KV if available
  if (env.AUTH_STORE) {
    try {
      await env.AUTH_STORE.put(`token:${payload.id}`, JSON.stringify({
        clientId,
        issued: payload.iat,
        expires: payload.exp
      }), { expirationTtl: 3600 });
    } catch (error) {
      console.error('Failed to store token in KV:', error);
    }
  }
  
  return {
    encoded: btoa(JSON.stringify(payload)),
    id: payload.id
  };
}

async function generateHMAC(data, secretKey) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secretKey);
  const msgData = encoder.encode(data);
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, msgData);
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function generateRandomId() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function errorResponse(status, message) {
  return new Response(JSON.stringify({
    error: message,
    timestamp: new Date().toISOString()
  }), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}