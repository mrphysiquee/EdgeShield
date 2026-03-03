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
- AUTH_STORE=KV namespace binding
*/

// ============ ONE-TIME URL (OTP) SYSTEM ============

// ============ SIMPLIFIED ONE-TIME URL SYSTEM ============

async function generateOneTimeUrl(request, env) {
    // Admin auth check
    const adminToken = request.headers.get('X-Admin-Token');
    if (!adminToken || adminToken !== env.ADMIN_TOKEN) {
        return errorResponse(403, 'Forbidden');
    }
    
    try {
        const { 
            clientId, 
            expiresIn = 3600,        // Custom expiry (seconds)
            maxUses = 1,             // Custom usage limit
            redirectPath = '/',      // Custom redirect path
            customId = null          // Custom ID for tracking
        } = await request.json();
        
        // Validate required fields
        if (!clientId) {
            return errorResponse(400, 'Missing clientId');
        }
        
        // Validate client
        const allowedClients = parseClientList(env.ALLOWED_CLIENTS);
        if (!allowedClients.includes(clientId)) {
            return errorResponse(400, 'Invalid client ID');
        }
        
        // Validate expiry (1 min to 30 days)
        if (expiresIn < 60 || expiresIn > 2592000) {
            return errorResponse(400, 'Expiry must be between 60s and 30 days');
        }
        
        // Validate max uses (1 to 1000)
        if (maxUses < 1 || maxUses > 1000) {
            return errorResponse(400, 'Max uses must be between 1 and 1000');
        }
        
        // Validate redirect path
        if (redirectPath && !redirectPath.startsWith('/')) {
            return errorResponse(400, 'Redirect path must start with /');
        }
        
        // Generate or use custom token
        const token = customId || generateSecureId();
        const expiresAt = Date.now() + (expiresIn * 1000);
        const createdAt = Date.now();
        
        // Store in KV
        if (env.AUTH_STORE) {
            const otpData = {
                clientId,
                created: createdAt,
                expiresAt,
                maxUses,
                usedCount: 0,
                status: 'active',
                redirectPath: redirectPath || '/',
                customId: customId || null,
                createdByIp: request.headers.get('CF-Connecting-IP'),
                createdByUserAgent: request.headers.get('User-Agent')?.substring(0, 200) || 'unknown'
            };
            
            await env.AUTH_STORE.put(`otp:${token}`, JSON.stringify(otpData), { 
                expirationTtl: expiresIn + 86400 // Extra 24 hour buffer
            });
            
            // Store customId mapping for easy lookup
            if (customId) {
                await env.AUTH_STORE.put(`otp:custom:${customId}`, token, {
                    expirationTtl: expiresIn + 86400
                });
            }
        }
        
        // Create access URL
        const baseUrl = `https://${new URL(request.url).hostname}`;
        const accessUrl = `${baseUrl}/access/${token}`;
        
        // Generate QR code URL (optional)
        const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(accessUrl)}`;
        
        return new Response(JSON.stringify({
            success: true,
            access_url: accessUrl,
            token: token,
            expires_at: new Date(expiresAt).toISOString(),
            expires_in: expiresIn,
            max_uses: maxUses,
            remaining_uses: maxUses,
            client_id: clientId,
            redirect_path: redirectPath || '/',
            custom_id: customId || null,
            qr_code_url: qrCodeUrl,
            created_at: new Date(createdAt).toISOString()
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
        
    } catch (error) {
        return errorResponse(400, 'Invalid request format');
    }
}

// ============ VALIDATE OTP TOKEN ============

async function validateOneTimeUrl(token, env) {
    if (!env.AUTH_STORE) {
        return { valid: false, reason: 'kv_not_configured' };
    }
    
    const tokenData = await env.AUTH_STORE.get(`otp:${token}`, 'json');
    if (!tokenData) {
        return { valid: false, reason: 'invalid_token' };
    }
    
    // Check status
    if (tokenData.status !== 'active') {
        return { valid: false, reason: tokenData.status };
    }
    
    // Check expiry
    if (Date.now() > tokenData.expiresAt) {
        // Auto-delete expired token
        await env.AUTH_STORE.delete(`otp:${token}`);
        if (tokenData.customId) {
            await env.AUTH_STORE.delete(`otp:custom:${tokenData.customId}`);
        }
        return { valid: false, reason: 'expired' };
    }
    
    // Check usage limit
    if (tokenData.usedCount >= tokenData.maxUses) {
        return { valid: false, reason: 'max_uses_exceeded' };
    }
    
    return {
        valid: true,
        clientId: tokenData.clientId,
        tokenData: tokenData,
        remainingUses: tokenData.maxUses - tokenData.usedCount,
        redirectPath: tokenData.redirectPath || '/'
    };
}

// ============ HANDLE OTP ACCESS ============

async function handleOneTimeAccess(request, env) {
    const url = new URL(request.url);
    const token = url.pathname.split('/access/')[1];
    
    if (!token) {
        return errorResponse(400, 'Missing access token');
    }
    
    // Validate token
    const validation = await validateOneTimeUrl(token, env);
    
    if (!validation.valid) {
        return errorResponse(401, `Access denied: ${validation.reason}`, {
            'X-OTP-Error': validation.reason,
            'X-OTP-Token': token
        });
    }
    
    // Increment usage count
    if (env.AUTH_STORE) {
        const updatedData = {
            ...validation.tokenData,
            usedCount: validation.tokenData.usedCount + 1,
            lastUsed: Date.now(),
            lastUsedFrom: request.headers.get('CF-Connecting-IP'),
            lastUsedUserAgent: request.headers.get('User-Agent')?.substring(0, 200) || 'unknown'
        };
        
        // If max uses reached, mark as used
        if (updatedData.usedCount >= updatedData.maxUses) {
            updatedData.status = 'used';
            updatedData.usedAt = Date.now();
        }
        
        await env.AUTH_STORE.put(
            `otp:${token}`, 
            JSON.stringify(updatedData),
            { 
                expirationTtl: Math.ceil((updatedData.expiresAt - Date.now()) / 1000) + 86400 
            }
        );
    }
    
    // Generate regular auth token
    const authToken = await createSecureToken(validation.clientId, env.SECRET_KEY, env, {
        otpToken: token,
        otpCustomId: validation.tokenData.customId,
        otpUsage: `${validation.tokenData.usedCount + 1}/${validation.tokenData.maxUses}`
    });
    
    // Set auth cookie
    const cookie = `cdn_auth_token=${authToken.encoded}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600`;
    
    // Handle response based on Accept header
    const accept = request.headers.get('Accept') || '';
    
    if (accept.includes('application/json')) {
        // API clients get JSON response
        return new Response(JSON.stringify({
            success: true,
            authenticated: true,
            client_id: validation.clientId,
            access_token: authToken.encoded,
            token_type: 'Bearer',
            expires_in: 3600,
            redirect_to: validation.redirectPath,
            otp_usage: `${validation.tokenData.usedCount}/${validation.tokenData.maxUses}`,
            otp_remaining: validation.remainingUses - 1,
            custom_id: validation.tokenData.customId || null
        }), {
            headers: {
                'Content-Type': 'application/json',
                'Set-Cookie': cookie
            }
        });
    } else {
        // Web clients get redirect
        return new Response('', {
            status: 302,
            headers: {
                'Location': validation.redirectPath,
                'Set-Cookie': cookie,
                'Cache-Control': 'no-store'
            }
        });
    }
}

// ============ CHECK TOKEN STATUS ============

async function getOneTimeUrlStatus(request, env, url) {
    // Admin auth check
    const adminToken = request.headers.get('X-Admin-Token');
    if (!adminToken || adminToken !== env.ADMIN_TOKEN) {
        return errorResponse(403, 'Forbidden');
    }
    
    const token = url.searchParams.get('token');
    const customId = url.searchParams.get('custom_id');
    
    if (!token && !customId) {
        return errorResponse(400, 'Missing token or custom_id parameter');
    }
    
    // Lookup by custom ID if provided
    let lookupToken = token;
    if (customId && !token) {
        lookupToken = await env.AUTH_STORE.get(`otp:custom:${customId}`);
        if (!lookupToken) {
            return errorResponse(404, 'Custom ID not found');
        }
    }
    
    const data = await env.AUTH_STORE.get(`otp:${lookupToken}`, 'json');
    if (!data) {
        return errorResponse(404, 'Token not found');
    }
    
    const now = Date.now();
    const isActive = data.status === 'active' && 
                    data.usedCount < data.maxUses && 
                    now < data.expiresAt;
    
    return new Response(JSON.stringify({
        token: lookupToken,
        custom_id: data.customId || null,
        client_id: data.clientId,
        status: data.status,
        is_active: isActive,
        created_at: new Date(data.created).toISOString(),
        expires_at: new Date(data.expiresAt).toISOString(),
        expires_in_seconds: Math.max(0, Math.floor((data.expiresAt - now) / 1000)),
        used_count: data.usedCount,
        max_uses: data.maxUses,
        remaining_uses: Math.max(0, data.maxUses - data.usedCount),
        redirect_path: data.redirectPath,
        created_by_ip: data.createdByIp,
        last_used: data.lastUsed ? new Date(data.lastUsed).toISOString() : null,
        last_used_from: data.lastUsedFrom || null
    }, null, 2), {
        headers: { 'Content-Type': 'application/json' }
    });
}

// ============ UPDATE TOKEN (EXTEND/RESET) ============

async function updateOneTimeUrl(request, env) {
    // Admin auth check
    const adminToken = request.headers.get('X-Admin-Token');
    if (!adminToken || adminToken !== env.ADMIN_TOKEN) {
        return errorResponse(403, 'Forbidden');
    }
    
    try {
        const { 
            token,
            custom_id,  // Alternative to token
            action,     // 'extend', 'reset_uses', 'change_path'
            value       // For extend: seconds, reset: number, path: string
        } = await request.json();
        
        if (!action) {
            return errorResponse(400, 'Missing action');
        }
        
        // Lookup by custom ID if no token
        let lookupToken = token;
        if (custom_id && !token) {
            lookupToken = await env.AUTH_STORE.get(`otp:custom:${custom_id}`);
            if (!lookupToken) {
                return errorResponse(404, 'Custom ID not found');
            }
        }
        
        if (!lookupToken) {
            return errorResponse(400, 'Missing token or custom_id');
        }
        
        // Get existing data
        const tokenData = await env.AUTH_STORE.get(`otp:${lookupToken}`, 'json');
        if (!tokenData) {
            return errorResponse(404, 'Token not found');
        }
        
        let updatedData = { ...tokenData };
        let message = '';
        
        switch (action) {
            case 'extend':
                if (!value || typeof value !== 'number' || value < 60 || value > 2592000) {
                    return errorResponse(400, 'Invalid extension value (60s to 30 days)');
                }
                updatedData.expiresAt = Date.now() + (value * 1000);
                message = `Extended by ${value} seconds`;
                break;
                
            case 'reset_uses':
                if (!value || typeof value !== 'number' || value < 1 || value > 1000) {
                    return errorResponse(400, 'Invalid uses value (1-1000)');
                }
                updatedData.usedCount = 0;
                updatedData.maxUses = value;
                updatedData.status = 'active';
                message = `Reset to ${value} uses`;
                break;
                
            case 'change_path':
                if (!value || typeof value !== 'string' || !value.startsWith('/')) {
                    return errorResponse(400, 'Invalid path (must start with /)');
                }
                updatedData.redirectPath = value;
                message = `Redirect path changed to ${value}`;
                break;
                
            default:
                return errorResponse(400, 'Invalid action');
        }
        
        // Update KV
        const newTtl = Math.ceil((updatedData.expiresAt - Date.now()) / 1000) + 86400;
        await env.AUTH_STORE.put(`otp:${lookupToken}`, JSON.stringify(updatedData), {
            expirationTtl: newTtl
        });
        
        return new Response(JSON.stringify({
            success: true,
            message: message,
            token: lookupToken,
            custom_id: updatedData.customId || null,
            remaining_uses: updatedData.maxUses - updatedData.usedCount,
            expires_at: new Date(updatedData.expiresAt).toISOString(),
            redirect_path: updatedData.redirectPath
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
        
    } catch (error) {
        return errorResponse(400, 'Invalid request');
    }
}

// ============ REVOKE TOKEN ============

async function revokeOneTimeUrl(request, env) {
    // Admin auth check
    const adminToken = request.headers.get('X-Admin-Token');
    if (!adminToken || adminToken !== env.ADMIN_TOKEN) {
        return errorResponse(403, 'Forbidden');
    }
    
    try {
        const { token, custom_id } = await request.json();
        
        // Lookup by custom ID
        let lookupToken = token;
        if (custom_id && !token) {
            lookupToken = await env.AUTH_STORE.get(`otp:custom:${custom_id}`);
            if (!lookupToken) {
                return errorResponse(404, 'Custom ID not found');
            }
        }
        
        if (!lookupToken) {
            return errorResponse(400, 'Missing token or custom_id');
        }
        
        const data = await env.AUTH_STORE.get(`otp:${lookupToken}`, 'json');
        if (!data) {
            return errorResponse(404, 'Token not found');
        }
        
        // Update status to revoked
        data.status = 'revoked';
        data.revokedAt = Date.now();
        data.revokedByIp = request.headers.get('CF-Connecting-IP');
        
        await env.AUTH_STORE.put(`otp:${lookupToken}`, JSON.stringify(data));
        
        return new Response(JSON.stringify({
            success: true,
            message: `Token ${lookupToken} revoked`,
            token: lookupToken,
            custom_id: data.customId || null,
            client_id: data.clientId,
            revoked_at: new Date(data.revokedAt).toISOString()
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
        
    } catch (error) {
        return errorResponse(400, 'Invalid request');
    }
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

// ============ MAIN WORKER HANDLER ============

// ============ MAIN WORKER HANDLER ============

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const startTime = Date.now();
        
        // ============ ONE-TIME URL ACCESS (HIGHEST PRIORITY) ============
        if (url.pathname.startsWith('/access/')) {
            return handleOneTimeAccess(request, env);
        }
        
        const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
        const userAgent = request.headers.get('User-Agent') || '';
        
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
            return generateAuthFailureResponse(request, authResult);
        }
        
        // ============ AUTHENTICATION SUCCESS ============
        await logAuthSuccess(request, authResult, env);
        
        // ============ RATE LIMITING ============
        if (env.AUTH_STORE && authResult.clientId) {
            const rateLimitResult = await enforceRateLimit(authResult.clientId, clientIp, env);
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

  // 4. Request Frequency (Basic)
  if (env.AUTH_STORE) {
      checks.scores.frequency = 'monitored';
  }

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

  // Security: Rate limit token requests by IP
  const clientIp = request.headers.get('CF-Connecting-IP');
  if (env.AUTH_STORE) {
      const tokenRateKey = `token_rate:ip:${clientIp}:${Math.floor(Date.now()/60000)}`;
      const tokenRate = await checkRateLimit(tokenRateKey, env, 10, 60);
      if (tokenRate.blocked) {
          return errorResponse(429, 'Too many token requests', {
              'Retry-After': tokenRate.retryAfter.toString()
          });
      }
  }

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

      // Store token metadata
      if (env.AUTH_STORE) {
          await storeTokenMetadata(token, env, {
              clientIp,
              userAgent: request.headers.get('User-Agent'),
              requestId: generateRequestId()
          });
      }

      await logSecurityEvent('token_issued', request, env, {
          clientId,
          tokenId: token.id,
          issuedAt: token.issued
      });

      // Return token
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

// ============ TOKEN CREATION & VALIDATION ============

async function createSecureToken(clientId, secretKey, env, metadata = {}) {
  const issued = Date.now();
  const expires = issued + 3600000;
  const tokenId = generateSecureId();

  const payload = {
      id: tokenId,
      cid: clientId,
      iat: issued,
      exp: expires,
      ver: '1.0'
  };

  const signature = await generateHMAC(JSON.stringify(payload), secretKey);
  payload.sig = signature;

  // Store token in KV if available
  if (env.AUTH_STORE) {
      await env.AUTH_STORE.put(`token:${payload.id}`, JSON.stringify({
          clientId,
          issued: payload.iat,
          expires: payload.exp
      }), { expirationTtl: 3600 });
  }

  return {
      id: tokenId,
      clientId,
      issued,
      expires,
      encoded: btoa(JSON.stringify(payload))
  };
}

async function validateBearerToken(token, env) {
  console.log('🔍 Token validation started');

  try {
      const tokenData = JSON.parse(atob(token));

      if (!tokenData.id || !tokenData.cid || !tokenData.iat || !tokenData.exp || !tokenData.sig) {
          return { valid: false, reason: 'token_invalid_structure' };
      }

      if (Date.now() > tokenData.exp) {
          return { valid: false, reason: 'token_expired' };
      }

      const signature = tokenData.sig;
      delete tokenData.sig;

      const expectedSig = await generateHMAC(JSON.stringify(tokenData), env.SECRET_KEY);

      if (!constantTimeCompare(signature, expectedSig)) {
          return { valid: false, reason: 'invalid_token_signature' };
      }

      // Check KV for revocation
      if (env.AUTH_STORE) {
          const stored = await env.AUTH_STORE.get(`token:${tokenData.id}`);
          if (!stored) {
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

async function storeTokenMetadata(token, env, metadata) {
  if (!env.AUTH_STORE) return;

  const tokenKey = `token:${token.id}`;
  const tokenData = {
      id: token.id,
      clientId: token.clientId,
      issued: token.issued,
      expires: token.expires,
      ip: metadata.clientIp,
      userAgent: metadata.userAgent?.substring(0, 200) || 'unknown',
      requestId: metadata.requestId,
      status: 'active'
  };

  await env.AUTH_STORE.put(tokenKey, JSON.stringify(tokenData), {
      expirationTtl: 7200
  });
}

// ============ HMAC AUTHENTICATION ============

async function validateHMACAuth(request, config) {
  console.log('🔐 HMAC validation started');

  const clientId = request.headers.get('X-Client-Key');
  const signature = request.headers.get('X-Signature');
  const timestamp = request.headers.get('X-Timestamp');
  const nonce = request.headers.get('X-Nonce');
  const requestId = request.headers.get('X-Request-ID') || generateRequestId();

  if (!clientId || !signature || !timestamp || !nonce) {
      console.log('❌ Missing HMAC headers');
      return { valid: false, reason: 'missing_headers' };
  }

  if (!config.allowedClients.includes(clientId)) {
      console.log(`❌ Client not allowed: ${clientId}`);
      return { valid: false, reason: 'invalid_client', clientId };
  }

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

  // Check nonce replay
  if (config.kvStore) {
      const nonceKey = `nonce:${clientId}:${nonce}`;
      const existing = await config.kvStore.get(nonceKey);
      if (existing) {
          console.log(`❌ Nonce reused: ${nonce}`);
          await logSecurityEvent('nonce_reuse', request, config.env, { clientId, nonce });
          return { valid: false, reason: 'nonce_reused' };
      }

      await config.kvStore.put(nonceKey, JSON.stringify({
          used: true,
          timestamp: Date.now(),
          requestId
      }), { expirationTtl: config.signatureTTL });
  }

  const url = new URL(request.url);
  const pathWithQuery = url.pathname + url.search;
  const dataToSign = `${request.method}:${pathWithQuery}:${timestamp}:${nonce}:${requestId}`;
  const expectedSignature = await generateHMAC(dataToSign, config.secretKey);

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

// ============ CREDENTIAL VALIDATION ============

async function validateClientCredentials(clientId, clientSecret, env) {
  console.log(`🔐 Credential validation for: ${clientId}`);

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

  if (typeof expectedSecret !== 'string' || expectedSecret.length < 8) {
      console.error(`❌ Invalid secret format for client: ${clientId}`);
      return false;
  }

  if (typeof clientSecret !== 'string') {
      console.log(`❌ Invalid client secret type for: ${clientId}`);
      return false;
  }

  const isValid = constantTimeCompare(clientSecret, expectedSecret);

  if (isValid) {
      console.log(`✅ Credentials valid for: ${clientId}`);
  } else {
      console.log(`❌ Credentials invalid for: ${clientId}`);
      if (env.AUTH_STORE) {
          const failKey = `auth_fail:${clientId}:${Math.floor(Date.now()/60000)}`;
          const current = parseInt(await env.AUTH_STORE.get(failKey) || '0');
          await env.AUTH_STORE.put(failKey, (current + 1).toString(), { expirationTtl: 300 });
      }
  }

  return isValid;
}

// ============ REQUEST FORWARDING ============

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

      const responseHeaders = new Headers(response.headers);

      if (!responseHeaders.has('X-Content-Type-Options')) {
          responseHeaders.set('X-Content-Type-Options', 'nosniff');
      }

      if (!responseHeaders.has('X-Frame-Options')) {
          responseHeaders.set('X-Frame-Options', 'DENY');
      }

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
          region: request.cf?.colo || 'unknown'
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
              kv_store: env.AUTH_STORE ? 'connected' : 'not_configured'
          },
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

  return errorResponse(404, 'Not found');
}

// ============ ADMIN REQUEST HANDLING ============

async function handleAdminRequest(request, env, url) {
    const adminToken = request.headers.get('X-Admin-Token');
    
    if (!adminToken || adminToken !== env.ADMIN_TOKEN) {
        return errorResponse(403, 'Forbidden');
    }
    
    // OTP Management Endpoints
    if (url.pathname === '/admin/otp/create' && request.method === 'POST') {
        return generateOneTimeUrl(request, env);
    }
    
    if (url.pathname === '/admin/otp/status' && request.method === 'GET') {
        return getOneTimeUrlStatus(request, env, url);
    }
    
    if (url.pathname === '/admin/otp/update' && request.method === 'POST') {
        return updateOneTimeUrl(request, env);
    }
    
    if (url.pathname === '/admin/otp/revoke' && request.method === 'POST') {
        return revokeOneTimeUrl(request, env);
    }
    
    // Existing Admin Endpoints
    if (url.pathname === '/admin/stats') {
        return await getAdminStats(request, env);
    }
    
    if (url.pathname === '/admin/clients') {
        return await manageClients(request, env);
    }
    
    if (url.pathname === '/admin/tokens') {
        return await manageTokens(request, env);
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

async function manageTokens(request, env) {
  if (!env.AUTH_STORE) {
      return errorResponse(503, 'KV store not configured');
  }

  if (request.method === 'GET') {
      const url = new URL(request.url);
      const clientId = url.searchParams.get('clientId');

      const tokens = {
          note: 'Token listing requires scanning all KV keys.',
          clientId,
          active_tokens: 'use_analytics_for_production'
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

          await env.AUTH_STORE.delete(`token:${tokenId}`);

          return new Response(JSON.stringify({
              success: true,
              message: `Token ${tokenId} revoked`,
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

// ============ UTILITY FUNCTIONS ============

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

async function enforceRateLimit(clientId, clientIp, env) {
  if (!env.AUTH_STORE) {
      return { blocked: false };
  }

  const window = parseInt(env.RATE_LIMIT_WINDOW || "60");
  const limit = parseInt(env.RATE_LIMIT_MAX || "100");
  const now = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(now / window) * window;

  const clientKey = `rate:client:${clientId}:${windowStart}`;
  const clientCount = parseInt(await env.AUTH_STORE.get(clientKey) || '0');

  const ipKey = `rate:ip:${clientIp}:${windowStart}`;
  const ipCount = parseInt(await env.AUTH_STORE.get(ipKey) || '0');

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

  await env.AUTH_STORE.put(clientKey, (clientCount + 1).toString(), { expirationTtl: window * 2 });
  await env.AUTH_STORE.put(ipKey, (ipCount + 1).toString(), { expirationTtl: window * 2 });

  return {
      blocked: false,
      limit,
      clientRemaining: limit - (clientCount + 1),
      ipRemaining: (limit * 2) - (ipCount + 1),
      resetTime: windowStart + window
  };
}

// ============ LOGGING ============

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
      ...data
  };

  const logMessage = `[${logEntry.level.toUpperCase()}] ${type}: ${JSON.stringify(logEntry)}`;
  if (logEntry.level === 'error' || logEntry.level === 'warning') {
      console.error(logMessage);
  } else {
      console.log(logMessage);
  }

  if (env.AUTH_STORE) {
      try {
          const logKey = `log:${type}:${Date.now()}:${Math.random().toString(36).substring(2, 9)}`;
          await env.AUTH_STORE.put(logKey, JSON.stringify(logEntry), {
              expirationTtl: 604800
          });
      } catch (error) {
          console.error('Failed to log to KV:', error);
      }
  }
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
      tokenId: authResult.tokenId,
      processingTime: Date.now() - parseInt(request.headers.get('X-Request-Start') || Date.now())
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
  return errorResponse(401, 'Authentication required', {
      'WWW-Authenticate': `Bearer realm="API", error="${authResult.reason}"`,
      'X-Auth-Methods': 'Bearer, HMAC-SHA256',
      'X-Auth-Failure-Reason': authResult.reason
  });
}

// ============ CONFIGURATION VALIDATION ============

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
      kvStore: env.AUTH_STORE,
      env: env
  };
}

// ============ PARSING FUNCTIONS ============

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

// ============ SECURITY FUNCTIONS ============

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

async function checkRateLimit(key, env, customLimit, customWindow) {
  if (!env.AUTH_STORE || !key) {
      return { blocked: false };
  }

  const window = customWindow || parseInt(env.RATE_LIMIT_WINDOW || "60");
  const limit = customLimit || parseInt(env.RATE_LIMIT_MAX || "100");
  const now = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(now / window) * window;

  const rateKey = `ratelimit:${key}:${windowStart}`;

  let current = 0;
  try {
      const stored = await env.AUTH_STORE.get(rateKey);
      current = stored ? parseInt(stored) : 0;
  } catch (error) {
      console.error('Rate limit read error:', error);
      return { blocked: false, limit, remaining: limit, resetTime: windowStart + window };
  }

  if (current >= limit) {
      const resetTime = windowStart + window;
      return {
          blocked: true,
          limit,
          remaining: 0,
          retryAfter: resetTime - now,
          resetTime
      };
  }

  try {
      await env.AUTH_STORE.put(rateKey, (current + 1).toString(), {
          expirationTtl: window * 2
      });
  } catch (error) {
      console.error('Rate limit write error:', error);
  }

  return {
      blocked: false,
      limit,
      remaining: limit - (current + 1),
      resetTime: windowStart + window
  };
}

async function forwardToOrigin(request, tunnelUrl, extraHeaders = {}) {
  const url = new URL(request.url);
  const targetUrl = new URL(tunnelUrl);
  targetUrl.pathname = url.pathname;
  targetUrl.search = url.search;

  const headers = new Headers(request.headers);

  ['X-Client-Key', 'X-Signature', 'X-Timestamp', 'X-Nonce', 'Authorization'].forEach(h => {
      headers.delete(h);
  });

  Object.entries(extraHeaders).forEach(([key, value]) => {
      headers.set(key, value);
  });

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