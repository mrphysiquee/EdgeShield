// admin.js - Complete Admin UI Worker
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const hostname = url.hostname;
    
    // Log request for debugging
    console.log(`[${new Date().toISOString()}] ${request.method} ${hostname}${pathname}`);
    
    // === PUBLIC ENDPOINTS ===
    if (['/health', '/status', '/ping', '/robots.txt'].includes(pathname)) {
      if (pathname === '/health') return healthCheck();
      if (pathname === '/status') return systemStatus(env);
      if (pathname === '/ping') return new Response('pong');
      if (pathname === '/robots.txt') return new Response(
        'User-agent: *\nDisallow: /admin/\nDisallow: /api/\nAllow: /health\nAllow: /status\nAllow: /ping',
        { headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'max-age=3600' } }
      );
    }
    
    // === ADMIN UI PAGES ===
    if (['/', '/dashboard', '/admin', '/login', '/logout'].includes(pathname)) {
      return handleUIPages(request, env, pathname);
    }
    
    // === PROXY ADMIN API CALLS TO YOUR API WORKER ===
    if (pathname.startsWith('/admin/')) {
      return proxyAdminAPI(request, env, pathname);
    }
    
    // === STATIC ASSETS ===
    if (pathname.match(/\.(css|js|png|jpg|ico|svg|woff|woff2)$/)) {
      return serveStaticAsset(pathname);
    }
    
    // === 404 FOR UNKNOWN ROUTES ===
    return new Response('Not Found', { status: 404 });
  }
};

// ========== ADMIN UI PAGES HANDLER ==========
async function handleUIPages(request, env, pathname) {
  const baseUrl = getBaseUrl(request);
  
  // Login page
  if (pathname === '/login') {
    if (request.method === 'POST') {
      return handleAdminLogin(request, env, baseUrl);
    }
    return serveLoginPage(baseUrl);
  }
  
  // Logout
  if (pathname === '/logout') {
    return handleLogout(baseUrl);
  }
  
  // Check authentication for protected pages
  const session = await getSession(request, env);
  if (!session) {
    return Response.redirect(`${baseUrl}/login`, 302);
  }
  
  // Dashboard/home pages
  if (pathname === '/') {
    return Response.redirect(`${baseUrl}/dashboard`, 302);
  }
  
  if (pathname === '/dashboard' || pathname === '/admin') {
    return serveDashboardPage(env, baseUrl, session);
  }
  
  return new Response('Not Found', { status: 404 });
}

// ========== SESSION MANAGEMENT ==========
async function getSession(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/admin_session=([^;]+)/);
  
  if (!match) return null;
  
  const sessionId = match[1];
  
  // Check in KV if available
  if (env.SESSIONS) {
    try {
      const session = await env.SESSIONS.get(sessionId, 'json');
      if (session && session.expires > Date.now()) {
        return session;
      }
    } catch (e) {
      console.error('Session error:', e);
    }
    return null;
  }
  
  // Simple session validation (for development)
  try {
    const decoded = atob(sessionId);
    const [token, timestamp] = decoded.split(':');
    if (token === env.ADMIN_TOKEN && Date.now() - parseInt(timestamp) < 86400000) {
      return { authenticated: true, timestamp: parseInt(timestamp) };
    }
  } catch (e) {
    return null;
  }
  
  return null;
}

async function createSession(adminToken, env) {
  const sessionId = btoa(`${adminToken}:${Date.now()}:${Math.random()}`).replace(/=/g, '');
  
  if (env.SESSIONS) {
    await env.SESSIONS.put(sessionId, JSON.stringify({
      authenticated: true,
      created: Date.now(),
      expires: Date.now() + 86400000, // 24 hours
      user: 'admin'
    }), { expirationTtl: 86400 });
  }
  
  return sessionId;
}

async function destroySession(sessionId, env) {
  if (env.SESSIONS && sessionId) {
    await env.SESSIONS.delete(sessionId);
  }
}

// ========== LOGIN HANDLING ==========
async function handleAdminLogin(request, env, baseUrl) {
  try {
    const formData = await request.formData();
    const enteredToken = formData.get('admin_token');
    
    console.log('Login attempt - Token entered (first 10 chars):', enteredToken?.substring(0, 10) + '...');
    console.log('Expected token (first 10 chars):', env.ADMIN_TOKEN?.substring(0, 10) + '...');
    
    if (!enteredToken) {
      return serveLoginPage(baseUrl, 'Please enter admin token');
    }
    
    // Trim and compare tokens
    if (enteredToken.trim() === env.ADMIN_TOKEN.trim()) {
      const sessionId = await createSession(enteredToken, env);
      
      return new Response(null, {
        status: 302,
        headers: {
          'Location': `${baseUrl}/dashboard`,
          'Set-Cookie': `admin_session=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`
        }
      });
    } else {
      return serveLoginPage(baseUrl, 'Invalid admin token');
    }
  } catch (error) {
    console.error('Login error:', error);
    return serveLoginPage(baseUrl, 'Login error: ' + error.message);
  }
}

// ========== PROXY TO API WORKER ==========
// ========== PROXY TO API WORKER (FIXED) ==========
async function proxyAdminAPI(request, env, pathname) {
  try {
    // Get the API worker URL from environment
    const apiBaseUrl = env.ORIGIN_BASE_URL || 'https://login.support-noreply.help';
    const targetUrl = `${apiBaseUrl}${pathname}`;
    
    console.log(`[API CALL] ${request.method} ${targetUrl}`);
    console.log(`[API CALL] Admin Token present: ${!!env.ADMIN_TOKEN}`);
    
    // Prepare headers for API request
    const headers = new Headers();
    
    // Set content type if there's a body
    if (request.method === 'POST' || request.method === 'PUT') {
      headers.set('Content-Type', 'application/json');
    }
    
    // ALWAYS send the admin token from environment
    headers.set('X-Admin-Token', env.ADMIN_TOKEN);
    headers.set('X-Forwarded-Host', new URL(request.url).host);
    headers.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP') || '');
    headers.set('User-Agent', 'Admin-UI-Worker/1.0');
    
    // Get request body if present
    let body = null;
    if (request.method === 'POST' || request.method === 'PUT') {
      try {
        body = await request.clone().text();
        console.log(`[API CALL] Request body: ${body.substring(0, 200)}...`);
      } catch (e) {
        console.log('[API CALL] No request body');
      }
    }
    
    // Forward the request to API worker
    const apiRequest = new Request(targetUrl, {
      method: request.method,
      headers: headers,
      body: body,
      redirect: 'manual'
    });
    
    console.log(`[API CALL] Sending request to API worker...`);
    
    // Make the API call with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
    
    try {
      const response = await fetch(apiRequest, { signal: controller.signal });
      clearTimeout(timeoutId);
      
      console.log(`[API CALL] Response status: ${response.status} ${response.statusText}`);
      
      // Get response body for debugging
      const responseText = await response.text();
      console.log(`[API CALL] Response body: ${responseText.substring(0, 500)}...`);
      
      // Return the API response
      return new Response(responseText, {
        status: response.status,
        statusText: response.statusText,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
      
    } catch (fetchError) {
      clearTimeout(timeoutId);
      console.error('[API CALL] Fetch error:', fetchError);
      
      if (fetchError.name === 'AbortError') {
        return jsonResponse({ 
          error: 'timeout', 
          message: 'API request timed out after 10 seconds' 
        }, 504);
      }
      
      throw fetchError;
    }
    
  } catch (error) {
    console.error('[API CALL] Proxy error:', error);
    return jsonResponse({ 
      error: 'proxy_error', 
      message: `Failed to connect to API: ${error.message}`,
      details: {
        api_url: env.ORIGIN_BASE_URL,
        endpoint: pathname,
        timestamp: new Date().toISOString()
      }
    }, 502);
  }
}
// ========== DASHBOARD PAGE ==========
async function serveDashboardPage(env, baseUrl, session) {
  const apiBaseUrl = env.ORIGIN_BASE_URL || 'https://login.support-noreply.help';
  
  // FIXED: Removed extra backticks and properly closed the template literal
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CDN OTP Admin Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
  <style>
    :root {
      --primary: #3b82f6;
      --primary-dark: #1d4ed8;
    }
    body { 
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
      min-height: 100vh;
    }
    .glass {
      background: rgba(255, 255, 255, 0.8);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.2);
    }
    .gradient-bg {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    .gradient-btn {
      background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
    }
    .gradient-btn:hover {
      background: linear-gradient(135deg, #1d4ed8 0%, #1e40af 100%);
    }
  </style>
</head>
<body class="min-h-screen">
  <div id="app" class="min-h-screen flex flex-col">
    <!-- Navigation -->
    <nav class="bg-white shadow-lg border-b border-gray-200">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex justify-between h-16">
          <div class="flex items-center">
            <div class="flex-shrink-0 flex items-center space-x-3">
              <div class="h-8 w-8 rounded-lg gradient-bg flex items-center justify-center">
                <i class="fas fa-shield-alt text-white"></i>
              </div>
              <span class="text-xl font-bold text-gray-900">CDN OTP Admin</span>
              <span class="px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800">v1.0</span>
            </div>
            <div class="hidden md:ml-6 md:flex md:space-x-8">
              <a href="${baseUrl}/dashboard" class="border-blue-500 text-gray-900 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">
                <i class="fas fa-tachometer-alt mr-2"></i> Dashboard
              </a>
              <a href="#otps" class="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">
                <i class="fas fa-key mr-2"></i> OTPs
              </a>
              <a href="#clients" class="border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">
                <i class="fas fa-users mr-2"></i> Clients
              </a>
            </div>
          </div>
          <div class="flex items-center">
            <div class="ml-3 relative">
              <div class="flex items-center space-x-4">
                <span class="text-sm text-gray-700 hidden md:inline">
                  <i class="fas fa-user-shield mr-1"></i> Administrator
                </span>
                <a href="${baseUrl}/logout" class="ml-4 px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white gradient-btn hover:shadow-md transition">
                  <i class="fas fa-sign-out-alt mr-2"></i> Logout
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </nav>

    <!-- Main Content -->
    <main class="flex-1">
      <div class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <!-- Stats Cards -->
        <div class="px-4 py-6 sm:px-0">
          <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="glass overflow-hidden shadow rounded-lg">
              <div class="p-5">
                <div class="flex items-center">
                  <div class="flex-shrink-0">
                    <div class="h-12 w-12 rounded-lg gradient-bg flex items-center justify-center">
                      <i class="fas fa-link text-white text-lg"></i>
                    </div>
                  </div>
                  <div class="ml-5">
                    <p class="text-sm font-medium text-gray-500">Active OTPs</p>
                    <p class="text-2xl font-bold text-gray-900" id="activeOtps">Loading...</p>
                  </div>
                </div>
              </div>
            </div>
            
            <div class="glass overflow-hidden shadow rounded-lg">
              <div class="p-5">
                <div class="flex items-center">
                  <div class="flex-shrink-0">
                    <div class="h-12 w-12 rounded-lg bg-green-500 flex items-center justify-center">
                      <i class="fas fa-users text-white text-lg"></i>
                    </div>
                  </div>
                  <div class="ml-5">
                    <p class="text-sm font-medium text-gray-500">Total Clients</p>
                    <p class="text-2xl font-bold text-gray-900" id="totalClients">Loading...</p>
                  </div>
                </div>
              </div>
            </div>
            
            <div class="glass overflow-hidden shadow rounded-lg">
              <div class="p-5">
                <div class="flex items-center">
                  <div class="flex-shrink-0">
                    <div class="h-12 w-12 rounded-lg bg-purple-500 flex items-center justify-center">
                      <i class="fas fa-chart-line text-white text-lg"></i>
                    </div>
                  </div>
                  <div class="ml-5">
                    <p class="text-sm font-medium text-gray-500">Today's Usage</p>
                    <p class="text-2xl font-bold text-gray-900" id="todaysUsage">Loading...</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Create OTP Card -->
          <div class="glass shadow rounded-lg p-6 mb-8" id="otps">
            <h2 class="text-2xl font-bold text-gray-900 mb-6 flex items-center">
              <div class="h-10 w-10 rounded-lg gradient-bg flex items-center justify-center mr-3">
                <i class="fas fa-plus text-white"></i>
              </div>
              Create One-Time URL
            </h2>
            
            <form id="createOtpForm" class="space-y-6">
              <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-2">
                    <i class="fas fa-id-card mr-2"></i>Custom ID (Optional)
                  </label>
                  <input type="text" name="customId" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" 
                    placeholder="e.g., invite-ceo-2024">
                  <p class="mt-1 text-sm text-gray-500">Unique identifier for tracking</p>
                </div>
                
                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-2">
                    <i class="fas fa-user-tag mr-2"></i>Client ID
                  </label>
                  <input type="text" name="clientId" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" 
                    value="client-1" required>
                  <p class="mt-1 text-sm text-gray-500">Which application can use this</p>
                </div>
              </div>
              
              <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-2">
                    <i class="fas fa-clock mr-2"></i>Expires In (seconds)
                  </label>
                  <div class="flex space-x-2 mb-2">
                    <button type="button" onclick="setExpiry(300)" class="flex-1 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg text-sm">5 min</button>
                    <button type="button" onclick="setExpiry(3600)" class="flex-1 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg text-sm">1 hour</button>
                    <button type="button" onclick="setExpiry(86400)" class="flex-1 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg text-sm">1 day</button>
                  </div>
                  <input type="number" id="expiresIn" name="expiresIn" value="3600" min="60" 
                    class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" required>
                </div>
                
                <div>
                  <label class="block text-sm font-medium text-gray-700 mb-2">
                    <i class="fas fa-repeat mr-2"></i>Maximum Uses
                  </label>
                  <div class="flex space-x-2 mb-2">
                    <button type="button" onclick="setMaxUses(1)" class="flex-1 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg text-sm">Single use</button>
                    <button type="button" onclick="setMaxUses(5)" class="flex-1 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg text-sm">5 uses</button>
                    <button type="button" onclick="setMaxUses(0)" class="flex-1 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg text-sm">Unlimited</button>
                  </div>
                  <input type="number" id="maxUses" name="maxUses" value="1" min="0" 
                    class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" required>
                </div>
              </div>
              
              <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">
                  <i class="fas fa-directions mr-2"></i>Redirect Path
                </label>
                <input type="text" name="redirectPath" value="/dashboard" 
                  class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" required>
                <p class="mt-1 text-sm text-gray-500">Where users go after OTP validation</p>
              </div>
              
              <div class="flex space-x-4">
                <button type="submit" class="flex-1 gradient-btn text-white font-semibold py-3 px-6 rounded-lg transition flex items-center justify-center hover:shadow-md">
                  <i class="fas fa-bolt mr-2"></i> Generate OTP URL
                </button>
                <button type="button" onclick="previewOTP()" class="px-6 py-3 border border-gray-300 rounded-lg hover:bg-gray-50">
                  <i class="fas fa-eye mr-2"></i> Preview
                </button>
              </div>
            </form>
            
            <!-- Result Display -->
            <div id="resultSection" class="mt-8 p-6 bg-gradient-to-r from-green-50 to-emerald-50 border border-green-200 rounded-xl hidden">
              <div class="flex items-center mb-4">
                <div class="h-10 w-10 rounded-full bg-green-100 flex items-center justify-center mr-3">
                  <i class="fas fa-check text-green-600"></i>
                </div>
                <div>
                  <h3 class="text-lg font-bold text-gray-900">OTP Created Successfully!</h3>
                  <p class="text-gray-600">Share this link with your user</p>
                </div>
              </div>
              
              <div class="mb-4">
                <label class="block text-sm font-medium text-gray-700 mb-2">OTP URL:</label>
                <div class="flex">
                  <input type="text" id="generatedUrl" readonly 
                    class="flex-1 px-4 py-3 bg-white border border-gray-300 rounded-l-lg font-mono text-sm">
                  <button onclick="copyToClipboard('generatedUrl')" class="px-4 gradient-btn text-white rounded-r-lg hover:shadow-md">
                    <i class="fas fa-copy"></i>
                  </button>
                </div>
              </div>
              
              <div class="grid grid-cols-2 gap-4 text-sm">
                <div class="p-3 bg-white rounded-lg">
                  <p class="text-gray-500">Expires:</p>
                  <p class="font-semibold" id="expiryTime">--:--</p>
                </div>
                <div class="p-3 bg-white rounded-lg">
                  <p class="text-gray-500">Uses Left:</p>
                  <p class="font-semibold" id="usesLeft">0</p>
                </div>
              </div>
            </div>
          </div>

          <!-- Quick Actions & API Reference -->
          <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <!-- Quick Actions -->
            <div class="glass shadow rounded-lg p-6">
              <h2 class="text-xl font-bold text-gray-900 mb-6 flex items-center">
                <i class="fas fa-bolt text-blue-600 mr-2"></i> Quick Actions
              </h2>
              <div class="space-y-4">
                <button onclick="checkOTPStatus()" class="w-full p-4 border border-gray-200 rounded-xl hover:bg-gray-50 text-left flex items-center">
                  <div class="h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center mr-3">
                    <i class="fas fa-search text-blue-600"></i>
                  </div>
                  <div>
                    <p class="font-medium text-gray-900">Check OTP Status</p>
                    <p class="text-sm text-gray-500">Verify active tokens</p>
                  </div>
                </button>
                
                <button onclick="listAllOTPs()" class="w-full p-4 border border-gray-200 rounded-xl hover:bg-gray-50 text-left flex items-center">
                  <div class="h-10 w-10 rounded-lg bg-green-100 flex items-center justify-center mr-3">
                    <i class="fas fa-list text-green-600"></i>
                  </div>
                  <div>
                    <p class="font-medium text-gray-900">List All OTPs</p>
                    <p class="text-sm text-gray-500">View all active tokens</p>
                  </div>
                </button>
              </div>
            </div>
            
            <!-- API Reference -->
            <div class="glass shadow rounded-lg p-6">
              <h2 class="text-xl font-bold text-gray-900 mb-6 flex items-center">
                <i class="fas fa-code text-gray-600 mr-2"></i> API Reference
              </h2>
              <div class="space-y-4">
                <div class="p-4 bg-gray-50 rounded-lg">
                  <div class="flex items-center mb-2">
                    <span class="px-2 py-1 bg-green-500 text-white rounded text-xs font-mono mr-2">POST</span>
                    <code class="text-sm">${apiBaseUrl}/admin/otp/create</code>
                  </div>
                  <p class="text-gray-600 text-sm">Create new OTP token</p>
                </div>
                
                <div class="p-4 bg-gray-50 rounded-lg">
                  <div class="flex items-center mb-2">
                    <span class="px-2 py-1 bg-yellow-500 text-white rounded text-xs font-mono mr-2">GET</span>
                    <code class="text-sm">${apiBaseUrl}/admin/otp/status</code>
                  </div>
                  <p class="text-gray-600 text-sm">Check token status</p>
                </div>
                
                <div class="p-4 bg-gray-50 rounded-lg">
                  <div class="flex items-center mb-2">
                    <span class="px-2 py-1 bg-red-500 text-white rounded text-xs font-mono mr-2">POST</span>
                    <code class="text-sm">${apiBaseUrl}/admin/otp/revoke</code>
                  </div>
                  <p class="text-gray-600 text-sm">Revoke active token</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>

    <!-- Footer -->
    <footer class="bg-white border-t border-gray-200 mt-12">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div class="flex flex-col md:flex-row justify-between items-center">
          <div class="mb-4 md:mb-0">
            <div class="flex items-center">
              <i class="fas fa-cloud text-blue-600 text-2xl mr-3"></i>
              <div>
                <p class="text-gray-900 font-semibold">CDN OTP Management System</p>
                <p class="text-gray-500 text-sm">Powered by Cloudflare Workers</p>
              </div>
            </div>
          </div>
          <div class="text-gray-500 text-sm">
            <p>© 2024 support-noreply.help • Admin UI v1.0.0</p>
          </div>
        </div>
      </div>
    </footer>
  </div>

  <!-- JavaScript -->
  <script>
  // Configuration
  const API_BASE = '${apiBaseUrl}';
  const ADMIN_TOKEN = '${env.ADMIN_TOKEN}';
  const ADMIN_UI_BASE = '${baseUrl}';
  
  console.log('[UI] Configuration:', { 
    API_BASE, 
    ADMIN_TOKEN_PRESENT: !!ADMIN_TOKEN,
    ADMIN_TOKEN_LENGTH: ADMIN_TOKEN?.length || 0,
    ADMIN_UI_BASE 
  });
  
  // DOM Elements
  const createOtpForm = document.getElementById('createOtpForm');
  const resultSection = document.getElementById('resultSection');
  const generatedUrl = document.getElementById('generatedUrl');
  const expiryTime = document.getElementById('expiryTime');
  const usesLeft = document.getElementById('usesLeft');
  
  // Create OTP via API Worker
  async function createOTP() {
    const formData = new FormData(createOtpForm);
    const data = {
      clientId: formData.get('clientId'),
      expiresIn: parseInt(formData.get('expiresIn')),
      maxUses: parseInt(formData.get('maxUses')),
      redirectPath: formData.get('redirectPath'),
      customId: formData.get('customId') || undefined
    };
    
    console.log('[UI] Creating OTP with data:', data);
    console.log('[UI] Calling API:', API_BASE + '/admin/otp/create');
    console.log('[UI] Admin token (first 20 chars):', ADMIN_TOKEN?.substring(0, 20) + '...');
    
    try {
      showLoader();
      
      const response = await fetch(API_BASE + '/admin/otp/create', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Token': ADMIN_TOKEN
        },
        body: JSON.stringify(data)
      });
      
      console.log('[UI] Response status:', response.status, response.statusText);
      
      const responseText = await response.text();
      console.log('[UI] Response text:', responseText);
      
      let result;
      try {
        result = JSON.parse(responseText);
      } catch (parseError) {
        console.error('[UI] Failed to parse JSON:', parseError);
        showNotification('API returned invalid JSON: ' + responseText.substring(0, 100), 'error');
        return;
      }
      
      console.log('[UI] Parsed result:', result);
      
      if (result.success) {
        // Display result
        generatedUrl.value = result.otp_url;
        expiryTime.textContent = result.expires_at ? new Date(result.expires_at).toLocaleString() : 'Unknown';
        usesLeft.textContent = result.max_uses || 'Unlimited';
        
        // Show result section
        resultSection.classList.remove('hidden');
        
        showNotification('OTP created successfully!', 'success');
      } else {
        showNotification('Error: ' + (result.message || result.error || 'Unknown error'), 'error');
      }
    } catch (error) {
      console.error('[UI] Create OTP error:', error);
      showNotification('Network error: ' + error.message, 'error');
    } finally {
      hideLoader();
    }
  }
  
  // Test API connection on page load
  async function testAPIConnection() {
    try {
      console.log('[UI] Testing API connection to:', API_BASE + '/health');
      
      const response = await fetch(API_BASE + '/health', {
        headers: {
          'X-Admin-Token': ADMIN_TOKEN
        }
      });
      
      const result = await response.json();
      console.log('[UI] API health check result:', result);
      
      if (response.ok) {
        console.log('[UI] API connection successful');
      } else {
        console.error('[UI] API health check failed:', result);
      }
    } catch (error) {
      console.error('[UI] API connection test failed:', error);
    }
  }
  
  // Check OTP status
  async function checkOTPStatus() {
    const customId = prompt('Enter Custom ID to check:');
    if (!customId) return;
    
    try {
      const response = await fetch(API_BASE + '/admin/otp/status?custom_id=' + encodeURIComponent(customId), {
        headers: {
          'X-Admin-Token': ADMIN_TOKEN
        }
      });
      
      const data = await response.json();
      
      if (data.success) {
        const otp = data.otp;
        const expiryDate = new Date(otp.expires_at);
        const now = new Date();
        const isExpired = expiryDate < now;
        const usesLeft = otp.max_uses - otp.used_count;
        
        const message = '<div class="space-y-2">' +
          '<p><strong class="text-gray-700">Custom ID:</strong> <span class="font-mono">' + otp.custom_id + '</span></p>' +
          '<p><strong class="text-gray-700">Client ID:</strong> ' + otp.client_id + '</p>' +
          '<p><strong class="text-gray-700">Status:</strong> ' +
            '<span class="px-2 py-1 text-xs font-semibold rounded-full ' + (isExpired ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800') + '">' +
              (isExpired ? '❌ Expired' : '✅ Active') +
            '</span>' +
          '</p>' +
          '<p><strong class="text-gray-700">Expires:</strong> ' + expiryDate.toLocaleString() + '</p>' +
          '<p><strong class="text-gray-700">Uses:</strong> ' + otp.used_count + '/' + (otp.max_uses || '∞') + ' (' + usesLeft + ' left)</p>' +
          '<p><strong class="text-gray-700">Redirect:</strong> ' + otp.redirect_path + '</p>' +
          '<p><strong class="text-gray-700">URL:</strong></p>' +
          '<code class="block text-xs bg-gray-100 p-2 rounded mt-1 overflow-x-auto">' + otp.otp_url + '</code>' +
        '</div>';
        
        showModal('OTP Status', message);
      } else {
        showNotification('OTP not found: ' + (data.message || ''), 'error');
      }
    } catch (error) {
      showNotification('Error checking status: ' + error.message, 'error');
    }
  }
  
  // List all OTPs
  async function listAllOTPs() {
    try {
      const response = await fetch(API_BASE + '/admin/otp/list', {
        headers: {
          'X-Admin-Token': ADMIN_TOKEN
        }
      });
      
      const data = await response.json();
      
      if (data.success && data.otps && data.otps.length > 0) {
        let html = '<div class="space-y-4">';
        data.otps.forEach(otp => {
          const expiryDate = new Date(otp.expires_at);
          const isExpired = expiryDate < new Date();
          
          html += '<div class="p-4 border border-gray-200 rounded-lg">' +
            '<div class="flex justify-between items-start">' +
              '<div>' +
                '<p class="font-medium text-gray-900">' + otp.custom_id + '</p>' +
                '<p class="text-sm text-gray-500">Client: ' + otp.client_id + '</p>' +
              '</div>' +
              '<span class="px-2 py-1 text-xs font-semibold rounded-full ' + (isExpired ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800') + '">' +
                (isExpired ? 'Expired' : 'Active') +
              '</span>' +
            '</div>' +
            '<div class="mt-2 text-sm text-gray-600">' +
              '<p>Expires: ' + expiryDate.toLocaleDateString() + ' ' + expiryDate.toLocaleTimeString() + '</p>' +
              '<p>Uses: ' + otp.used_count + '/' + otp.max_uses + '</p>' +
              '<p class="truncate">URL: <span class="font-mono text-xs">' + otp.otp_url + '</span></p>' +
            '</div>' +
          '</div>';
        });
        html += '</div>';
        
        showModal('All OTPs', html);
      } else {
        showModal('All OTPs', '<p class="text-gray-500">No OTPs found or endpoint not implemented yet.</p>');
      }
    } catch (error) {
      showNotification('Error listing OTPs: ' + error.message, 'error');
    }
  }
  
  // Load stats
  async function loadStats() {
    try {
      const response = await fetch(API_BASE + '/admin/stats', {
        headers: { 'X-Admin-Token': ADMIN_TOKEN }
      });
      
      if (response.ok) {
        const data = await response.json();
        // Update UI with stats if available
        if (data.stats && data.stats.otps) {
          document.getElementById('activeOtps').textContent = data.stats.otps.active || 0;
          document.getElementById('totalClients').textContent = data.stats.clients ? data.stats.clients.length : 0;
          document.getElementById('todaysUsage').textContent = data.stats.usage ? data.stats.usage.last_24h || 0 : 0;
        }
      }
    } catch (error) {
      console.log('Stats load failed (might not be implemented):', error.message);
    }
  }
  
  // Utility functions
  function setExpiry(seconds) {
    document.getElementById('expiresIn').value = seconds;
  }
  
  function setMaxUses(uses) {
    document.getElementById('maxUses').value = uses;
  }
  
  function previewOTP() {
    const formData = new FormData(createOtpForm);
    const customId = formData.get('customId') || 'Not set';
    const clientId = formData.get('clientId');
    const expiresIn = formData.get('expiresIn');
    const maxUses = formData.get('maxUses');
    const redirectPath = formData.get('redirectPath');
    
    const preview = '<div class="space-y-3">' +
      '<p><strong class="text-gray-700">Custom ID:</strong> ' + customId + '</p>' +
      '<p><strong class="text-gray-700">Client ID:</strong> ' + clientId + '</p>' +
      '<p><strong class="text-gray-700">Expires in:</strong> ' + expiresIn + ' seconds (' + (expiresIn/3600).toFixed(1) + ' hours)</p>' +
      '<p><strong class="text-gray-700">Max Uses:</strong> ' + (maxUses === '0' ? 'Unlimited' : maxUses) + '</p>' +
      '<p><strong class="text-gray-700">Redirects to:</strong> ' + redirectPath + '</p>' +
      '<p class="mt-4 text-gray-500 italic text-sm">Note: This is a preview. Actual OTP will be generated via API.</p>' +
    '</div>';
    
    showModal('OTP Preview', preview);
  }
  
  function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    element.select();
    document.execCommand('copy');
    
    // Visual feedback
    const button = element.nextElementSibling;
    const originalHTML = button.innerHTML;
    button.innerHTML = '<i class="fas fa-check"></i>';
    button.classList.add('bg-green-600');
    
    setTimeout(() => {
      button.innerHTML = originalHTML;
      button.classList.remove('bg-green-600');
    }, 2000);
    
    showNotification('Copied to clipboard!', 'success');
  }
  
  function showNotification(message, type = 'info') {
    // Remove existing notifications
    const existing = document.querySelector('.notification');
    if (existing) existing.remove();
    
    const colors = {
      success: 'bg-green-500',
      error: 'bg-red-500',
      info: 'bg-blue-500'
    };
    
    const iconClass = {
      success: 'fa-check-circle',
      error: 'fa-exclamation-circle',
      info: 'fa-info-circle'
    };
    
    const notification = document.createElement('div');
    notification.className = 'notification fixed top-4 right-4 ' + colors[type] + ' text-white px-6 py-3 rounded-lg shadow-lg z-50 transform transition-transform duration-300 translate-x-full';
    notification.innerHTML = '<div class="flex items-center">' +
      '<i class="fas ' + iconClass[type] + ' mr-2"></i>' +
      '<span>' + message + '</span>' +
    '</div>';
    
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
      notification.classList.remove('translate-x-full');
    }, 10);
    
    // Remove after 3 seconds
    setTimeout(() => {
      notification.classList.add('translate-x-full');
      setTimeout(() => notification.remove(), 300);
    }, 3000);
  }
  
  function showLoader() {
    const loader = document.createElement('div');
    loader.id = 'globalLoader';
    loader.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    loader.innerHTML = '<div class="bg-white rounded-xl p-8 shadow-2xl">' +
      '<div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>' +
      '<p class="text-gray-700">Processing...</p>' +
    '</div>';
    document.body.appendChild(loader);
  }
  
  function hideLoader() {
    const loader = document.getElementById('globalLoader');
    if (loader) loader.remove();
  }
  
  function showModal(title, content) {
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4';
    modal.innerHTML = '<div class="bg-white rounded-xl max-w-lg w-full max-h-[80vh] overflow-auto">' +
      '<div class="p-6">' +
        '<div class="flex justify-between items-center mb-4">' +
          '<h3 class="text-xl font-bold text-gray-900">' + title + '</h3>' +
          '<button onclick="this.closest(\'.fixed\').remove()" class="text-gray-400 hover:text-gray-600">' +
            '<i class="fas fa-times"></i>' +
          '</button>' +
        '</div>' +
        '<div class="prose prose-sm max-w-none">' +
          content +
        '</div>' +
        '<div class="mt-6 flex justify-end">' +
          '<button onclick="this.closest(\'.fixed\').remove()" class="px-4 py-2 bg-gray-200 hover:bg-gray-300 rounded-lg">' +
            'Close' +
          '</button>' +
        '</div>' +
      '</div>' +
    '</div>';
    document.body.appendChild(modal);
  }
  
  // Call test on load
  document.addEventListener('DOMContentLoaded', function() {
    testAPIConnection();
    loadStats();
    
    // Form submission
    if (createOtpForm) {
      createOtpForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        await createOTP();
      });
    }
  });
  </script>
</body>
</html>`;
  
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
      'Cache-Control': 'no-cache'
    }
  });
}

// ========== LOGOUT HANDLER ==========
async function handleLogout(baseUrl) {
  return new Response(null, {
    status: 302,
    headers: {
      'Location': `${baseUrl}/login`,
      'Set-Cookie': 'admin_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
    }
  });
}

// ========== HELPER FUNCTIONS ==========
function getBaseUrl(request) {
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
  });
}

function healthCheck() {
  return jsonResponse({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'admin-ui-worker',
    version: '1.0.0'
  });
}

function systemStatus(env) {
  const apiBaseUrl = env.ORIGIN_BASE_URL || 'https://login.support-noreply.help';
  
  return jsonResponse({
    system: 'CDN OTP Management System',
    environment: 'production',
    workers: {
      admin_ui: 'admin-ui.support-noreply.help',
      api: apiBaseUrl,
      tunnel: env.TUNNEL_URL || 'Not configured'
    },
    config: {
      allowed_clients: env.ALLOWED_CLIENTS ? JSON.parse(env.ALLOWED_CLIENTS) : [],
      api_paths: env.API_PATHS ? JSON.parse(env.API_PATHS) : [],
      auth_enabled: env.AUTH_ENABLED === 'true'
    }
  });
}

function serveStaticAsset(pathname) {
  // Simple static file serving
  if (pathname.endsWith('.css')) {
    const css = `/* Static CSS */\nbody { font-family: Arial, sans-serif; }`;
    return new Response(css, {
      headers: {
        'Content-Type': 'text/css',
        'Cache-Control': 'public, max-age=31536000'
      }
    });
  }
  
  if (pathname.endsWith('.js')) {
    const js = `// Static JavaScript\nconsole.log('Admin UI loaded');`;
    return new Response(js, {
      headers: {
        'Content-Type': 'application/javascript',
        'Cache-Control': 'public, max-age=31536000'
      }
    });
  }
  
  if (pathname.match(/\.(png|jpg|ico|svg)$/)) {
    // Return a simple 1x1 transparent pixel for images
    const transparentPixel = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';
    return Response.redirect(transparentPixel, 302);
  }
  
  return new Response('Not Found', { status: 404 });
}