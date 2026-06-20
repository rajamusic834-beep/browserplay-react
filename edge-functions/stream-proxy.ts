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
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
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
const RATE_LIMIT_MAX = 60;

const rateLimitStore = new Map<string, { count: number; windowStart: number }>();

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

  try {
    return new URL(referer).origin;
  } catch {
    return '';
  }
}

function isOriginAllowed(origin: string): boolean {
  if (!origin) return false;
  if (ALLOWED_ORIGIN_DOMAINS.has(origin)) return true;
  for (const { before, after } of ALLOWED_WILDCARDS) {
    if (origin.startsWith(before) && origin.endsWith(after)) return true;
  }
  return false;
}

function getSecurityHeaders(): Record<string, string> {
  return SECURITY_HEADERS;
}

function corsHeaders(origin: string): Record<string, string> {
  return {
    ...BASE_CORS_HEADERS,
    ...(isOriginAllowed(origin) ? { 'Access-Control-Allow-Origin': origin } : {}),
  };
}

function json(data: any, status: number, origin: string, requestId?: string): Response {
  const headers = { ...corsHeaders(origin), ...getSecurityHeaders(), 'Content-Type': 'application/json' };
  if (requestId) headers['X-Request-ID'] = requestId;
  return new Response(JSON.stringify(data), { status, headers });
}

function base64UrlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, '=');
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

async function verifyJWT(token: string, secret: string): Promise<any> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format');

  const [headerStr, payloadStr, sigStr] = parts;

  const headerJson = new TextDecoder().decode(base64UrlDecode(headerStr));
  const header = JSON.parse(headerJson);
  if (header.alg !== 'HS256') throw new Error('Unsupported JWT algorithm');

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );

  const valid = await crypto.subtle.verify(
    'HMAC',
    key,
    base64UrlDecode(sigStr),
    new TextEncoder().encode(`${headerStr}.${payloadStr}`),
  );

  if (!valid) throw new Error('Invalid JWT signature');

  const decoded = new TextDecoder().decode(base64UrlDecode(payloadStr));
  const payload = JSON.parse(decoded);

  if (payload.exp && payload.exp <= (Date.now() / 1000)) {
    throw new Error('JWT expired');
  }

  return payload;
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

const URLS: Record<string, string> = {
  rajamods7_lite: 'https://secure-gateway-public.vercel.app/api/allstream.json',
  jiotv: 'https://secure-gateway-public.vercel.app/api/stream.json',
  jtvplus: 'https://proxysites.noobworker.workers.dev/playlist.json',
  zee5: 'https://yr5i4zr5.us-east.insforge.app/api/storage/buckets/tseT/objects/zee5.json',
  fancode: 'https://secure-gateway-public.vercel.app/api/fancode.json',
  backuptv: 'https://allinonereborn.online/jiotv-m3u/playlist698.m3u8',
  tataplay: 'https://allinonereborn.online/tatatv-web/xchannels.json',
  airtel: 'https://allinonereborn.online/airteltv-web/xchannels.json',
  iptv: 'https://api.codetabs.com/v1/proxy?quest=https://allinonereborn.online//iptv-web/xchannels.json',
  star: 'https://secure-gateway-public.vercel.app/api/star.json',
};

export default async function handler(request: Request): Promise<Response> {
  const requestId = request.headers.get('x-request-id') || crypto.randomUUID();
  const requestOrigin = getRequestOrigin(request);
  const clientIp = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';

  log('info', 'request received', { requestId, method: request.method, origin: requestOrigin, appId: new URL(request.url).searchParams.get('app_id') || 'none' });

  if (request.method === 'OPTIONS') {
    if (!isOriginAllowed(requestOrigin)) {
      log('warn', 'origin rejected (preflight)', { requestId, origin: requestOrigin });
      return json({ error: 'Forbidden' }, 403, requestOrigin, requestId);
    }
    return new Response(null, {
      status: 204,
      headers: { ...corsHeaders(requestOrigin), ...getSecurityHeaders(), 'X-Request-ID': requestId },
    });
  }

  const authHeader = request.headers.get('authorization') || '';
  if (!authHeader.startsWith('Bearer ')) {
    log('warn', 'missing auth header', { requestId });
    return json({ error: 'Authentication required' }, 401, requestOrigin, requestId);
  }

  const jwtSecret = Deno.env.get('JWT_SECRET') || '';
  let payload: any;
  try {
    payload = await verifyJWT(authHeader.slice(7), jwtSecret);
  } catch (err) {
    log('warn', 'JWT verification failed', { requestId, error: String(err) });
    return json({ error: 'Authentication required' }, 401, requestOrigin, requestId);
  }

  if (payload.iss !== 'insforge' || !payload.sub) {
    log('warn', 'JWT payload validation failed', { requestId, iss: payload.iss, sub: !!payload.sub });
    return json({ error: 'Authentication required' }, 401, requestOrigin, requestId);
  }

  if (payload.aud && payload.aud !== 'stream-proxy') {
    log('warn', 'JWT audience mismatch', { requestId, aud: payload.aud });
    return json({ error: 'Authentication required' }, 401, requestOrigin, requestId);
  }

  const userRateKey = `user:${payload.sub}`;
  const ipRateKey = `ip:${clientIp}`;

  const userLimit = checkRateLimit(userRateKey);
  const ipLimit = checkRateLimit(ipRateKey);

  const rateHeaders: Record<string, string> = {
    'X-RateLimit-Limit': String(RATE_LIMIT_MAX),
    'X-RateLimit-Remaining': String(Math.min(userLimit.remaining, ipLimit.remaining)),
    'X-RateLimit-Reset': String(Math.ceil(Math.min(userLimit.resetMs, ipLimit.resetMs) / 1000)),
  };

  if (!userLimit.allowed || !ipLimit.allowed) {
    log('warn', 'rate limit exceeded', { requestId, sub: payload.sub, ip: clientIp });
    const headers = { ...corsHeaders(requestOrigin), ...getSecurityHeaders(), ...rateHeaders, 'X-Request-ID': requestId, 'Retry-After': String(Math.ceil(Math.min(userLimit.resetMs, ipLimit.resetMs) / 1000)) };
    return new Response(JSON.stringify({ error: 'Too many requests' }), { status: 429, headers: { ...headers, 'Content-Type': 'application/json' } });
  }

  if (!isOriginAllowed(requestOrigin)) {
    log('warn', 'origin not allowed', { requestId, origin: requestOrigin });
    return json({ error: 'Forbidden' }, 403, requestOrigin, requestId);
  }

  const url = new URL(request.url);
  const appId = url.searchParams.get('app_id');
  if (!appId) {
    log('warn', 'missing app_id', { requestId });
    return json({ error: 'Missing app_id parameter' }, 400, requestOrigin, requestId);
  }

  const fetchUrl = URLS[appId];
  if (!fetchUrl) {
    log('warn', 'unknown app', { requestId, appId });
    return json({ error: `Unknown app: ${appId}` }, 404, requestOrigin, requestId);
  }

  const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
  const originalReferer = request.headers.get('referer') || requestOrigin || 'https://rajamods7-live-tv.pages.dev/';

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const upstream = await fetch(fetchUrl, {
      signal: controller.signal,
      headers: {
        'User-Agent': userAgent,
        'Referer': originalReferer,
        'Origin': requestOrigin || 'https://rajamods7-live-tv.pages.dev',
      },
    });
    clearTimeout(timeout);

    const contentType = upstream.headers.get('content-type') || 'application/json';

    log('info', 'upstream success', { requestId, appId, status: upstream.status, contentLength: upstream.headers.get('content-length') });

    return new Response(upstream.body, {
      status: upstream.status,
      headers: { ...corsHeaders(requestOrigin), ...getSecurityHeaders(), ...rateHeaders, 'X-Request-ID': requestId, 'Content-Type': contentType },
    });
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      log('error', 'upstream timeout', { requestId, appId, fetchUrl });
    } else {
      log('error', 'upstream fetch failed', { requestId, appId, error: String(err) });
    }
    return json({ error: 'Upstream fetch failed' }, 502, requestOrigin, requestId);
  }
}
