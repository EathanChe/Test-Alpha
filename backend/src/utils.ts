const encoder = new TextEncoder();
const decoder = new TextDecoder();
const DEFAULT_TOKEN_SECRET = 'dev-token-secret';

export type SessionPayload = {
  playerId: string;
  hallId: string;
  name: string;
  ver: number;
  exp: number;
};

export function base64UrlEncode(data: ArrayBuffer | Uint8Array) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlDecode(data: string) {
  const padded = data.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(data.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

const DEFAULT_CORS_ORIGINS = ['http://localhost:5173', 'http://127.0.0.1:5173'];

export type CorsOptions = {
  origin?: string | null;
  allowedOrigins?: string[];
};

export function parseCorsOrigins(raw?: string | null) {
  if (!raw) return DEFAULT_CORS_ORIGINS;
  const origins = raw
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  return origins.length > 0 ? origins : DEFAULT_CORS_ORIGINS;
}

export function resolveCorsOrigin(requestOrigin: string | null, allowedOrigins: string[]) {
  if (allowedOrigins.includes('*')) {
    return '*';
  }
  if (requestOrigin && allowedOrigins.includes(requestOrigin)) {
    return requestOrigin;
  }
  return allowedOrigins[0] ?? '';
}

export function corsHeaders(options: CorsOptions = {}, init?: HeadersInit) {
  const headers = new Headers(init);
  const allowedOrigins = options.allowedOrigins ?? DEFAULT_CORS_ORIGINS;
  const resolvedOrigin = resolveCorsOrigin(options.origin ?? null, allowedOrigins);
  if (resolvedOrigin) {
    headers.set('Access-Control-Allow-Origin', resolvedOrigin);
    if (resolvedOrigin !== '*') {
      headers.set('Vary', 'Origin');
    }
  }
  headers.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return headers;
}

export function jsonResponse(payload: unknown, init: ResponseInit = {}, cors?: CorsOptions) {
  const headers = corsHeaders(cors, init.headers);
  headers.set('Content-Type', 'application/json');
  const status = init.status ?? 200;
  if (status === 204 || status === 205 || status === 304) {
    return new Response(null, { ...init, status, headers });
  }
  return new Response(JSON.stringify(payload), { ...init, status, headers });
}

export async function readJson<T>(request: Request): Promise<T> {
  const body = await request.json();
  return body as T;
}

export async function hashPassword(password: string, salt?: string) {
  const resolvedSalt = salt ?? base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: encoder.encode(resolvedSalt),
      iterations: 100_000,
      hash: 'SHA-256',
    },
    key,
    256,
  );
  return { hash: base64UrlEncode(bits), salt: resolvedSalt };
}

export async function verifyPassword(password: string, salt: string, hash: string) {
  const result = await hashPassword(password, salt);
  return result.hash === hash;
}

export async function createSessionToken(payload: SessionPayload, secret: string) {
  const data = encoder.encode(JSON.stringify(payload));
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, data);
  return `${base64UrlEncode(data)}.${base64UrlEncode(signature)}`;
}

export async function verifySessionToken(token: string, secret: string) {
  const [payloadPart, signaturePart] = token.split('.');
  if (!payloadPart || !signaturePart) return null;
  const payloadBytes = base64UrlDecode(payloadPart);
  const signatureBytes = base64UrlDecode(signaturePart);
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const ok = await crypto.subtle.verify('HMAC', key, signatureBytes, payloadBytes);
  if (!ok) return null;
  const payload = JSON.parse(decoder.decode(payloadBytes)) as SessionPayload;
  if (payload.exp && Date.now() > payload.exp) return null;
  return payload;
}

export function randomHallCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i += 1) {
    code += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return code;
}

export function resolveTokenSecret(secret?: string | null) {
  const trimmed = secret?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : DEFAULT_TOKEN_SECRET;
}
