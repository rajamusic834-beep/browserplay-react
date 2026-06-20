const ALLOWED_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:3001',
  'https://crispy-couscous-xx5q9q5jqpp29xpr-3000.app.github.dev',
  'https://rajamods7-live-tv.pages.dev',
];

const ALLOWED_ORIGIN_DOMAINS = new Set(
  ALLOWED_ORIGINS.filter(o => !o.includes('*'))
);

const ALLOWED_WILDCARDS = ALLOWED_ORIGINS
  .filter(o => o.includes('*'))
  .map(o => {
    const [before, after] = o.split('*');
    return { before, after };
  });

const BASE_CORS_HEADERS = {
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Vary': 'Origin',
};

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 20;

const rateLimitStore = new Map<string, { count: number; windowStart: number }>();

const MAX_BODY_BYTES = 256;

let instanceId: string;
{
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  instanceId = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function getRequestOrigin(request: Request): string {
  const origin = request.headers.get('origin');
  if (origin) return origin;
  const referer = request.headers.get('referer');
  if (!referer) return '';
  try { return new URL(referer).origin; } catch { return ''; }
}

function isOriginAllowed(origin: string): boolean {
  if (!origin) return false;
  if (ALLOWED_ORIGIN_DOMAINS.has(origin)) return true;
  for (const { before, after } of ALLOWED_WILDCARDS) {
    if (origin.startsWith(before) && origin.endsWith(after)) return true;
  }
  return false;
}

function corsHeaders(origin: string): Record<string, string> {
  return {
    ...BASE_CORS_HEADERS,
    ...(isOriginAllowed(origin) ? { 'Access-Control-Allow-Origin': origin } : {}),
  };
}

function json(data: any, status: number, origin: string, requestId?: string): Response {
  const headers = { ...corsHeaders(origin), ...SECURITY_HEADERS, 'Content-Type': 'application/json' };
  if (requestId) headers['X-Request-ID'] = requestId;
  return new Response(JSON.stringify(data), { status, headers });
}

function base64UrlEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function createJWT(secret: string, sub: string, ttlSeconds: number): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: 'insforge',
    sub,
    aud: 'stream-proxy',
    iat: now,
    exp: now + ttlSeconds,
  };

  const encode = (obj: any) => base64UrlEncode(new TextEncoder().encode(JSON.stringify(obj)));
  const headerB64 = encode(header);
  const payloadB64 = encode(payload);

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const sig = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`${headerB64}.${payloadB64}`),
  );

  return `${headerB64}.${payloadB64}.${base64UrlEncode(new Uint8Array(sig))}`;
}

function checkRateLimit(key: string): { allowed: boolean; remaining: number; resetMs: number } {
  const now = Date.now();
  const entry = rateLimitStore.get(key);
  if (!entry || now >= entry.windowStart + RATE_LIMIT_WINDOW_MS) {
    rateLimitStore.set(key, { count: 1, windowStart: now });
    return { allowed: true, remaining: RATE_LIMIT_MAX - 1, resetMs: RATE_LIMIT_WINDOW_MS };
  }
  const remaining = RATE_LIMIT_MAX - entry.count;
  if (entry.count >= RATE_LIMIT_MAX) {
    const resetMs = entry.windowStart + RATE_LIMIT_WINDOW_MS - now;
    return { allowed: false, remaining: 0, resetMs: Math.max(resetMs, 0) };
  }
  entry.count++;
  return { allowed: true, remaining: remaining - 1, resetMs: entry.windowStart + RATE_LIMIT_WINDOW_MS - now };
}

function log(level: string, msg: string, meta?: Record<string, unknown>): void {
  const entry = { ts: new Date().toISOString(), level, msg, ...meta, instance: instanceId };
  if (level === 'error') {
    console.error(JSON.stringify(entry));
  } else {
    console.log(JSON.stringify(entry));
  }
}

export default async function handler(request: Request): Promise<Response> {
  const requestId = request.headers.get('x-request-id') || crypto.randomUUID();
  const requestOrigin = getRequestOrigin(request);
  const clientIp = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';

  log('info', 'token request received', { requestId, method: request.method, origin: requestOrigin });

  if (request.method === 'OPTIONS') {
    if (!isOriginAllowed(requestOrigin)) {
      return json({ error: 'Forbidden' }, 403, requestOrigin, requestId);
    }
    return new Response(null, {
      status: 204,
      headers: { ...corsHeaders(requestOrigin), ...SECURITY_HEADERS, 'X-Request-ID': requestId },
    });
  }

  if (request.method !== 'POST') {
    return json({ error: 'Method not allowed' }, 405, requestOrigin, requestId);
  }

  if (!isOriginAllowed(requestOrigin)) {
    log('warn', 'origin rejected', { requestId, origin: requestOrigin });
    return json({ error: 'Forbidden' }, 403, requestOrigin, requestId);
  }

  const ipLimit = checkRateLimit(`ip:${clientIp}`);
  if (!ipLimit.allowed) {
    log('warn', 'rate limit exceeded', { requestId, ip: clientIp });
    const headers = { ...corsHeaders(requestOrigin), ...SECURITY_HEADERS, 'X-Request-ID': requestId, 'Retry-After': String(Math.ceil(ipLimit.resetMs / 1000)), 'X-RateLimit-Limit': String(RATE_LIMIT_MAX), 'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': String(Math.ceil(ipLimit.resetMs / 1000)) };
    return new Response(JSON.stringify({ error: 'Too many requests' }), { status: 429, headers: { ...headers, 'Content-Type': 'application/json' } });
  }

  const contentType = request.headers.get('content-type') || '';
  if (contentType && !contentType.includes('application/json')) {
    log('warn', 'invalid content type', { requestId, contentType });
    return json({ error: 'Bad request' }, 400, requestOrigin, requestId);
  }

  const contentLength = parseInt(request.headers.get('content-length') || '0', 10);
  if (contentLength > MAX_BODY_BYTES) {
    log('warn', 'body too large', { requestId, contentLength });
    return json({ error: 'Bad request' }, 400, requestOrigin, requestId);
  }

  const anonKey = Deno.env.get('ANON_KEY') || '';
  if (!anonKey) {
    log('error', 'ANON_KEY not configured', { requestId });
    return json({ error: 'Server configuration error' }, 500, requestOrigin, requestId);
  }

  const authHeader = request.headers.get('authorization') || '';
  if (!authHeader.startsWith('Bearer ')) {
    log('warn', 'missing auth header', { requestId });
    return json({ error: 'Authentication required' }, 401, requestOrigin, requestId);
  }

  const providedKey = authHeader.slice(7);

  if (providedKey !== anonKey) {
    log('warn', 'invalid anon key', { requestId });
    return json({ error: 'Authentication required' }, 401, requestOrigin, requestId);
  }

  const jwtSecret = Deno.env.get('JWT_SECRET') || '';
  if (!jwtSecret) {
    log('error', 'JWT_SECRET not configured', { requestId });
    return json({ error: 'Server configuration error' }, 500, requestOrigin, requestId);
  }

  const ttlSeconds = 60 * 15;

  try {
    const token = await createJWT(jwtSecret, 'anon', ttlSeconds);
    log('info', 'token issued', { requestId });
    return json({ token, expiresIn: ttlSeconds }, 200, requestOrigin, requestId);
  } catch (err) {
    log('error', 'token generation failed', { requestId, error: String(err) });
    return json({ error: 'Token generation failed' }, 500, requestOrigin, requestId);
  }
}
