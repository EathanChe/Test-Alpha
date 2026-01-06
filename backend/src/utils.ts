const encoder = new TextEncoder();
const decoder = new TextDecoder();

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

const CORS_ALLOW_ORIGIN = 'http://localhost:5173';

export function corsHeaders(init?: HeadersInit) {
  const headers = new Headers(init);
  headers.set('Access-Control-Allow-Origin', CORS_ALLOW_ORIGIN);
  headers.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return headers;
}

export function jsonResponse(payload: unknown, init: ResponseInit = {}) {
  const headers = corsHeaders(init.headers);
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
