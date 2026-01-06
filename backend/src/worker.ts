import { HallRoom } from './hallRoom';
import {
  createSessionToken,
  hashPassword,
  jsonResponse,
  randomHallCode,
  readJson,
  verifyPassword,
  verifySessionToken,
} from './utils';

export { HallRoom };

export interface Env {
  DB: D1Database;
  HALL_ROOM: DurableObjectNamespace;
  TOKEN_SECRET: string;
}

type HallRow = {
  id: string;
  code: string;
  name: string;
  password_hash: string;
  password_salt: string;
  phase: string;
  day_number: number;
  status: string;
  storyteller_key: string;
};

type CreateHallBody = {
  name: string;
  password: string;
};

type JoinHallBody = {
  playerName: string;
  password: string;
};

type ResetDayBody = {
  storytellerKey: string;
};

const MAX_MESSAGES = 50;
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;

export default {
  async fetch(request: Request, env: Env) {
    if (request.method === 'OPTIONS') {
      return jsonResponse({ ok: true }, { status: 204 });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/api/halls' && request.method === 'POST') {
      return handleCreateHall(request, env);
    }

    if (path === '/api/halls' && request.method === 'GET') {
      return handleListHalls(env);
    }

    const joinMatch = path.match(/^\/api\/halls\/([^/]+)\/join$/);
    if (joinMatch && request.method === 'POST') {
      return handleJoinHall(request, env, joinMatch[1]);
    }

    const hallMatch = path.match(/^\/api\/halls\/([^/]+)$/);
    if (hallMatch && request.method === 'GET') {
      return handleGetHall(env, hallMatch[1]);
    }

    const messagesMatch = path.match(/^\/api\/halls\/([^/]+)\/messages$/);
    if (messagesMatch && request.method === 'GET') {
      return handleGetMessages(request, env, messagesMatch[1]);
    }

    const rosterMatch = path.match(/^\/api\/halls\/([^/]+)\/roster$/);
    if (rosterMatch && request.method === 'GET') {
      return handleGetRoster(request, env, rosterMatch[1]);
    }

    const resetMatch = path.match(/^\/api\/halls\/([^/]+)\/admin\/reset-day$/);
    if (resetMatch && request.method === 'POST') {
      return handleResetDay(request, env, resetMatch[1]);
    }

    const wsMatch = path.match(/^\/ws\/halls\/([^/]+)$/);
    if (wsMatch) {
      return handleWebSocket(request, env, wsMatch[1]);
    }

    return jsonResponse({ error: 'Not found' }, { status: 404 });
  },
};

async function handleCreateHall(request: Request, env: Env) {
  const body = await readJson<CreateHallBody>(request);
  const name = body.name?.trim();
  const password = body.password?.trim();
  if (!name || !password) {
    return jsonResponse({ error: '缺少大厅名称或密码' }, { status: 400 });
  }

  const { hash, salt } = await hashPassword(password);
  const hallId = crypto.randomUUID();
  const hallCode = await generateUniqueHallCode(env);
  const storytellerKey = crypto.randomUUID();
  const now = Date.now();

  await env.DB.prepare(
    'INSERT INTO halls (id, code, name, password_hash, password_salt, phase, day_number, status, storyteller_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
  )
    .bind(hallId, hallCode, name, hash, salt, 'DAY', 1, 'active', storytellerKey, now, now)
    .run();

  return jsonResponse({ hallId, hallCode, storytellerKey });
}

async function handleListHalls(env: Env) {
  const result = await env.DB.prepare(
    `SELECT
      h.id,
      h.code,
      h.name,
      h.day_number as dayNumber,
      h.phase,
      h.created_at as createdAt,
      (
        SELECT COUNT(1) FROM players p WHERE p.hall_id = h.id AND p.is_online = 1
      ) as onlineCount
    FROM halls h
    WHERE h.status = 'active'
    ORDER BY h.created_at DESC`,
  ).all();

  return jsonResponse({ halls: result.results });
}

async function handleJoinHall(request: Request, env: Env, code: string) {
  const body = await readJson<JoinHallBody>(request);
  const playerName = body.playerName?.trim();
  const password = body.password?.trim();
  if (!playerName || !password) {
    return jsonResponse({ error: '缺少昵称或密码' }, { status: 400 });
  }

  const hall = await env.DB.prepare(
    'SELECT id, name, code, password_hash, password_salt, phase, day_number FROM halls WHERE code = ? AND status = ? LIMIT 1',
  )
    .bind(code, 'active')
    .first<HallRow>();

  if (!hall) {
    return jsonResponse({ error: '大厅不存在' }, { status: 404 });
  }

  const passwordOk = await verifyPassword(password, hall.password_salt, hall.password_hash);
  if (!passwordOk) {
    return jsonResponse({ error: '密码不正确' }, { status: 401 });
  }

  const now = Date.now();
  const existingPlayer = await env.DB.prepare(
    'SELECT id, session_version FROM players WHERE hall_id = ? AND name = ? LIMIT 1',
  )
    .bind(hall.id, playerName)
    .first<{ id: string; session_version: number }>();

  let playerId = crypto.randomUUID();
  let sessionVersion = 1;

  if (existingPlayer) {
    playerId = existingPlayer.id;
    sessionVersion = existingPlayer.session_version + 1;
    await env.DB.prepare(
      'UPDATE players SET session_version = ?, is_online = 1, last_seen_at = ? WHERE id = ?',
    )
      .bind(sessionVersion, now, playerId)
      .run();
  } else {
    await env.DB.prepare(
      'INSERT INTO players (id, hall_id, name, session_version, is_online, last_seen_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    )
      .bind(playerId, hall.id, playerName, sessionVersion, 1, now, now)
      .run();
  }

  const sessionToken = await createSessionToken(
    {
      playerId,
      hallId: hall.id,
      name: playerName,
      ver: sessionVersion,
      exp: now + SESSION_TTL_MS,
    },
    env.TOKEN_SECRET,
  );

  return jsonResponse({
    playerId,
    sessionToken,
    hall: {
      id: hall.id,
      code: hall.code,
      name: hall.name,
      dayNumber: hall.day_number,
      phase: hall.phase,
    },
  });
}

async function handleGetHall(env: Env, code: string) {
  const hall = await env.DB.prepare(
    'SELECT id, code, name, day_number as dayNumber, phase FROM halls WHERE code = ? AND status = ? LIMIT 1',
  )
    .bind(code, 'active')
    .first();

  if (!hall) {
    return jsonResponse({ error: '大厅不存在' }, { status: 404 });
  }

  return jsonResponse({ hall });
}

async function handleGetMessages(request: Request, env: Env, code: string) {
  const hall = await env.DB.prepare('SELECT id FROM halls WHERE code = ? AND status = ? LIMIT 1')
    .bind(code, 'active')
    .first<{ id: string }>();

  if (!hall) {
    return jsonResponse({ error: '大厅不存在' }, { status: 404 });
  }

  const token = getToken(request);
  const session = await requireSession(env, hall.id, token);
  if (!session) {
    return jsonResponse({ error: '未授权' }, { status: 401 });
  }

  const limit = Math.min(Number(new URL(request.url).searchParams.get('limit') ?? MAX_MESSAGES), 100);
  const result = await env.DB.prepare(
    'SELECT id, hall_id as hallId, player_name as sender, content, created_at as createdAt FROM messages WHERE hall_id = ? ORDER BY created_at DESC LIMIT ?',
  )
    .bind(hall.id, limit)
    .all();

  const messages = result.results.slice().reverse();
  return jsonResponse({ messages });
}

async function handleGetRoster(request: Request, env: Env, code: string) {
  const hall = await env.DB.prepare('SELECT id FROM halls WHERE code = ? AND status = ? LIMIT 1')
    .bind(code, 'active')
    .first<{ id: string }>();

  if (!hall) {
    return jsonResponse({ error: '大厅不存在' }, { status: 404 });
  }

  const token = getToken(request);
  const session = await requireSession(env, hall.id, token);
  if (!session) {
    return jsonResponse({ error: '未授权' }, { status: 401 });
  }

  const result = await env.DB.prepare(
    'SELECT name, is_online as isOnline FROM players WHERE hall_id = ? ORDER BY created_at',
  )
    .bind(hall.id)
    .all();

  return jsonResponse({ players: result.results });
}

async function handleResetDay(request: Request, env: Env, code: string) {
  const body = await readJson<ResetDayBody>(request);
  const storytellerKey = body.storytellerKey?.trim();
  if (!storytellerKey) {
    return jsonResponse({ error: '缺少 storytellerKey' }, { status: 400 });
  }

  const hall = await env.DB.prepare('SELECT id, storyteller_key FROM halls WHERE code = ? LIMIT 1')
    .bind(code)
    .first<HallRow>();

  if (!hall || hall.storyteller_key !== storytellerKey) {
    return jsonResponse({ error: '无权限操作' }, { status: 403 });
  }

  const now = Date.now();
  await env.DB.prepare('UPDATE halls SET day_number = 1, phase = ?, updated_at = ? WHERE id = ?')
    .bind('DAY', now, hall.id)
    .run();
  await env.DB.prepare('DELETE FROM messages WHERE hall_id = ?').bind(hall.id).run();

  const stub = env.HALL_ROOM.get(env.HALL_ROOM.idFromName(hall.id));
  await stub.fetch('https://hall-room/broadcast', {
    method: 'POST',
    body: JSON.stringify({ type: 'system', message: '说书人已重置为第 1 天，聊天记录已清空。' }),
  });

  const updated = await env.DB.prepare(
    'SELECT id, code, name, day_number as dayNumber, phase FROM halls WHERE id = ? LIMIT 1',
  )
    .bind(hall.id)
    .first();

  return jsonResponse({ hall: updated });
}

async function handleWebSocket(request: Request, env: Env, code: string) {
  const hall = await env.DB.prepare('SELECT id FROM halls WHERE code = ? AND status = ? LIMIT 1')
    .bind(code, 'active')
    .first<{ id: string }>();

  if (!hall) {
    return new Response('大厅不存在', { status: 404 });
  }

  const token = new URL(request.url).searchParams.get('token');
  if (!token) {
    return new Response('缺少 token', { status: 401 });
  }

  const stub = env.HALL_ROOM.get(env.HALL_ROOM.idFromName(hall.id));
  const headers = new Headers(request.headers);
  headers.set('X-Hall-Id', hall.id);
  headers.set('X-Session-Token', token);

  return stub.fetch('https://hall-room/connect', {
    method: 'GET',
    headers,
  });
}

async function generateUniqueHallCode(env: Env) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const code = randomHallCode();
    const existing = await env.DB.prepare('SELECT id FROM halls WHERE code = ? LIMIT 1').bind(code).first();
    if (!existing) return code;
  }
  throw new Error('无法生成唯一大厅码');
}

function getToken(request: Request) {
  const auth = request.headers.get('Authorization');
  if (auth && auth.startsWith('Bearer ')) {
    return auth.slice(7);
  }
  return new URL(request.url).searchParams.get('token');
}

async function requireSession(env: Env, hallId: string, token: string | null) {
  if (!token) return null;
  const payload = await verifySessionToken(token, env.TOKEN_SECRET);
  if (!payload || payload.hallId !== hallId) return null;

  const player = await env.DB.prepare('SELECT session_version FROM players WHERE id = ? AND hall_id = ?')
    .bind(payload.playerId, hallId)
    .first<{ session_version: number }>();

  if (!player || player.session_version !== payload.ver) return null;
  return payload;
}
