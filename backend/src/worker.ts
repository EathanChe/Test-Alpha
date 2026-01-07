import { HallRoom } from './hallRoom';
import {
  CorsOptions,
  corsHeaders,
  createSessionToken,
  hashPassword,
  jsonResponse,
  parseCorsOrigins,
  randomHallCode,
  readJson,
  resolveTokenSecret,
  verifyPassword,
  verifySessionToken,
} from './utils';

export { HallRoom };

export interface Env {
  DB: D1Database;
  HALL_ROOM: DurableObjectNamespace;
  TOKEN_SECRET: string;
  CORS_ORIGINS?: string;
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

type AdvancePhaseBody = {
  storytellerKey: string;
  action: 'END_DAY' | 'START_DAY';
};

type CreatePrivateRequestBody = {
  targetName: string;
};

type RespondPrivateRequestBody = {
  response: 'ACCEPT' | 'REJECT';
};

const MAX_MESSAGES = 50;
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;

export default {
  async fetch(request: Request, env: Env) {
    const cors = buildCorsOptions(request, env);
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(cors),
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/api/halls' && request.method === 'POST') {
      return handleCreateHall(request, env, cors);
    }

    if (path === '/api/halls' && request.method === 'GET') {
      return handleListHalls(env, cors);
    }

    const joinMatch = path.match(/^\/api\/halls\/([^/]+)\/join$/);
    if (joinMatch && request.method === 'POST') {
      return handleJoinHall(request, env, joinMatch[1], cors);
    }

    const hallMatch = path.match(/^\/api\/halls\/([^/]+)$/);
    if (hallMatch && request.method === 'GET') {
      return handleGetHall(env, hallMatch[1], cors);
    }

    const messagesMatch = path.match(/^\/api\/halls\/([^/]+)\/messages$/);
    if (messagesMatch && request.method === 'GET') {
      return handleGetMessages(request, env, messagesMatch[1], cors);
    }

    const rosterMatch = path.match(/^\/api\/halls\/([^/]+)\/roster$/);
    if (rosterMatch && request.method === 'GET') {
      return handleGetRoster(request, env, rosterMatch[1], cors);
    }

    const resetMatch = path.match(/^\/api\/halls\/([^/]+)\/admin\/reset-day$/);
    if (resetMatch && request.method === 'POST') {
      return handleResetDay(request, env, resetMatch[1], cors);
    }

    const phaseMatch = path.match(/^\/api\/halls\/([^/]+)\/admin\/phase$/);
    if (phaseMatch && request.method === 'POST') {
      return handleAdvancePhase(request, env, phaseMatch[1], cors);
    }

    const privateRequestMatch = path.match(/^\/api\/halls\/([^/]+)\/private-requests$/);
    if (privateRequestMatch && request.method === 'POST') {
      return handleCreatePrivateRequest(request, env, privateRequestMatch[1], cors);
    }

    const privateRespondMatch = path.match(/^\/api\/halls\/([^/]+)\/private-requests\/([^/]+)\/respond$/);
    if (privateRespondMatch && request.method === 'POST') {
      return handleRespondPrivateRequest(request, env, privateRespondMatch[1], privateRespondMatch[2], cors);
    }

    const wsMatch = path.match(/^\/ws\/halls\/([^/]+)$/);
    if (wsMatch) {
      return handleWebSocket(request, env, wsMatch[1]);
    }

    return jsonResponse({ error: 'Not found' }, { status: 404 }, cors);
  },
};

async function handleCreateHall(request: Request, env: Env, cors: CorsOptions) {
  const body = await readJson<CreateHallBody>(request);
  const name = body.name?.trim();
  const password = body.password?.trim();
  if (!name || !password) {
    return jsonResponse({ error: '缺少大厅名称或密码' }, { status: 400 }, cors);
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

  return jsonResponse({ hallId, hallCode, storytellerKey }, {}, cors);
}

async function handleListHalls(env: Env, cors: CorsOptions) {
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

  return jsonResponse({ halls: result.results }, {}, cors);
}

async function handleJoinHall(request: Request, env: Env, code: string, cors: CorsOptions) {
  const body = await readJson<JoinHallBody>(request);
  const playerName = body.playerName?.trim();
  const password = body.password?.trim();
  if (!playerName || !password) {
    return jsonResponse({ error: '缺少昵称或密码' }, { status: 400 }, cors);
  }

  const hall = await env.DB.prepare(
    'SELECT id, name, code, password_hash, password_salt, phase, day_number FROM halls WHERE code = ? AND status = ? LIMIT 1',
  )
    .bind(code, 'active')
    .first<HallRow>();

  if (!hall) {
    return jsonResponse({ error: '大厅不存在' }, { status: 404 }, cors);
  }

  const passwordOk = await verifyPassword(password, hall.password_salt, hall.password_hash);
  if (!passwordOk) {
    return jsonResponse({ error: '密码不正确' }, { status: 401 }, cors);
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
    getTokenSecret(env),
  );

  return jsonResponse(
    {
      playerId,
      sessionToken,
      hall: {
        id: hall.id,
        code: hall.code,
        name: hall.name,
        dayNumber: hall.day_number,
        phase: hall.phase,
      },
    },
    undefined,
    cors,
  );
}

async function handleGetHall(env: Env, code: string, cors: CorsOptions) {
  const hall = await env.DB.prepare(
    'SELECT id, code, name, day_number as dayNumber, phase FROM halls WHERE code = ? AND status = ? LIMIT 1',
  )
    .bind(code, 'active')
    .first();

  if (!hall) {
    return jsonResponse({ error: '大厅不存在' }, { status: 404 }, cors);
  }

  return jsonResponse({ hall }, {}, cors);
}

async function handleGetMessages(request: Request, env: Env, code: string, cors: CorsOptions) {
  const hall = await env.DB.prepare('SELECT id FROM halls WHERE code = ? AND status = ? LIMIT 1')
    .bind(code, 'active')
    .first<{ id: string }>();

  if (!hall) {
    return jsonResponse({ error: '大厅不存在' }, { status: 404 }, cors);
  }

  const token = getToken(request);
  const session = await requireSession(env, hall.id, token);
  if (!session) {
    return jsonResponse({ error: '未授权' }, { status: 401 }, cors);
  }

  const limit = Math.min(Number(new URL(request.url).searchParams.get('limit') ?? MAX_MESSAGES), 100);
  const result = await env.DB.prepare(
    'SELECT id, hall_id as hallId, player_name as sender, content, created_at as createdAt FROM messages WHERE hall_id = ? ORDER BY created_at DESC LIMIT ?',
  )
    .bind(hall.id, limit)
    .all();

  const messages = result.results.slice().reverse();
  return jsonResponse({ messages }, {}, cors);
}

async function handleGetRoster(request: Request, env: Env, code: string, cors: CorsOptions) {
  const hall = await env.DB.prepare('SELECT id FROM halls WHERE code = ? AND status = ? LIMIT 1')
    .bind(code, 'active')
    .first<{ id: string }>();

  if (!hall) {
    return jsonResponse({ error: '大厅不存在' }, { status: 404 }, cors);
  }

  const token = getToken(request);
  const session = await requireSession(env, hall.id, token);
  if (!session) {
    return jsonResponse({ error: '未授权' }, { status: 401 }, cors);
  }

  const result = await env.DB.prepare(
    `SELECT
      p.name as name,
      p.is_online as isOnline,
      EXISTS (
        SELECT 1
        FROM private_session_members m
        JOIN private_sessions s ON s.id = m.session_id
        WHERE s.hall_id = p.hall_id AND s.status = 'ACTIVE' AND m.player_id = p.id
      ) as inPrivate
    FROM players p
    WHERE p.hall_id = ?
    ORDER BY p.created_at`,
  )
    .bind(hall.id)
    .all();

  return jsonResponse({ players: result.results }, {}, cors);
}

async function handleResetDay(request: Request, env: Env, code: string, cors: CorsOptions) {
  const body = await readJson<ResetDayBody>(request);
  const storytellerKey = body.storytellerKey?.trim();
  if (!storytellerKey) {
    return jsonResponse({ error: '缺少 storytellerKey' }, { status: 400 }, cors);
  }

  const hall = await env.DB.prepare('SELECT id, storyteller_key FROM halls WHERE code = ? LIMIT 1')
    .bind(code)
    .first<HallRow>();

  if (!hall || hall.storyteller_key !== storytellerKey) {
    return jsonResponse({ error: '无权限操作' }, { status: 403 }, cors);
  }

  const now = Date.now();
  await env.DB.prepare('UPDATE halls SET day_number = 1, phase = ?, updated_at = ? WHERE id = ?')
    .bind('DAY', now, hall.id)
    .run();
  await env.DB.prepare('DELETE FROM messages WHERE hall_id = ?').bind(hall.id).run();
  await env.DB.prepare('DELETE FROM private_requests WHERE hall_id = ?').bind(hall.id).run();
  await env.DB.prepare('DELETE FROM private_messages WHERE session_id IN (SELECT id FROM private_sessions WHERE hall_id = ?)').bind(hall.id).run();
  await env.DB.prepare('DELETE FROM private_session_members WHERE session_id IN (SELECT id FROM private_sessions WHERE hall_id = ?)').bind(hall.id).run();
  await env.DB.prepare('DELETE FROM private_sessions WHERE hall_id = ?').bind(hall.id).run();

  const updated = await env.DB.prepare(
    'SELECT id, code, name, day_number as dayNumber, phase FROM halls WHERE id = ? LIMIT 1',
  )
    .bind(hall.id)
    .first();

  await broadcastToHall(env, hall.id, {
    type: 'hall:update',
    hall: updated as { id: string; code: string; name: string; dayNumber: number; phase: string },
  });
  await broadcastToHall(env, hall.id, {
    type: 'system',
    message: '说书人已重置为第 1 天，聊天与私聊记录已清空。',
  });

  return jsonResponse({ hall: updated }, {}, cors);
}

async function handleAdvancePhase(request: Request, env: Env, code: string, cors: CorsOptions) {
  const body = await readJson<AdvancePhaseBody>(request);
  const storytellerKey = body.storytellerKey?.trim();
  if (!storytellerKey || !body.action) {
    return jsonResponse({ error: '缺少 storytellerKey 或 action' }, { status: 400 }, cors);
  }

  const hall = await env.DB.prepare(
    'SELECT id, day_number as dayNumber, phase, storyteller_key FROM halls WHERE code = ? LIMIT 1',
  )
    .bind(code)
    .first<HallRow & { dayNumber: number }>();

  if (!hall || hall.storyteller_key !== storytellerKey) {
    return jsonResponse({ error: '无权限操作' }, { status: 403 }, cors);
  }

  const now = Date.now();
  let nextPhase = hall.phase;
  let nextDay = hall.dayNumber;

  if (body.action === 'END_DAY') {
    nextPhase = 'NIGHT';
  } else if (body.action === 'START_DAY') {
    nextPhase = 'DAY';
    nextDay = hall.dayNumber + 1;
  }

  await env.DB.prepare('UPDATE halls SET phase = ?, day_number = ?, updated_at = ? WHERE id = ?')
    .bind(nextPhase, nextDay, now, hall.id)
    .run();

  if (body.action === 'END_DAY') {
    const activeSessions = await env.DB.prepare(
      'SELECT id FROM private_sessions WHERE hall_id = ? AND status = ?',
    )
      .bind(hall.id, 'ACTIVE')
      .all<{ id: string }>();

    await env.DB.prepare(
      'UPDATE private_sessions SET status = ?, ended_at = ?, ended_by_name = ? WHERE hall_id = ? AND status = ?',
    )
      .bind('ENDED', now, 'SYSTEM', hall.id, 'ACTIVE')
      .run();

    await env.DB.prepare(
      "UPDATE private_requests SET status = 'REJECTED', responded_at = ? WHERE hall_id = ? AND status = 'PENDING'",
    )
      .bind(now, hall.id)
      .run();

    for (const session of activeSessions.results) {
      const members = await env.DB.prepare(
        'SELECT player_id as playerId FROM private_session_members WHERE session_id = ?',
      )
        .bind(session.id)
        .all<{ playerId: string }>();
      await broadcastToHall(env, hall.id, {
        type: 'private:session-end',
        sessionId: session.id,
        endedByName: 'SYSTEM',
        recipients: members.results.map((member) => member.playerId),
      });
    }
  }

  const updated = await env.DB.prepare(
    'SELECT id, code, name, day_number as dayNumber, phase FROM halls WHERE id = ? LIMIT 1',
  )
    .bind(hall.id)
    .first();

  await broadcastToHall(env, hall.id, {
    type: 'hall:update',
    hall: updated as { id: string; code: string; name: string; dayNumber: number; phase: string },
  });

  if (body.action === 'END_DAY') {
    await broadcastToHall(env, hall.id, {
      type: 'system',
      message: '已进入黑夜，公开聊天与私聊已暂停。',
    });
  }

  return jsonResponse({ hall: updated }, {}, cors);
}

async function handleCreatePrivateRequest(request: Request, env: Env, code: string, cors: CorsOptions) {
  const body = await readJson<CreatePrivateRequestBody>(request);
  const targetName = body.targetName?.trim();
  if (!targetName) {
    return jsonResponse({ error: '缺少目标昵称' }, { status: 400 }, cors);
  }

  const hall = await env.DB.prepare('SELECT id, day_number as dayNumber, phase FROM halls WHERE code = ? LIMIT 1')
    .bind(code)
    .first<{ id: string; dayNumber: number; phase: string }>();

  if (!hall) {
    return jsonResponse({ error: '大厅不存在' }, { status: 404 }, cors);
  }

  if (hall.phase === 'NIGHT') {
    return jsonResponse({ error: '黑夜中无法发起私聊' }, { status: 403 }, cors);
  }

  const token = getToken(request);
  const session = await requireSession(env, hall.id, token);
  if (!session) {
    return jsonResponse({ error: '未授权' }, { status: 401 }, cors);
  }

  if (targetName === session.name) {
    return jsonResponse({ error: '不能邀请自己' }, { status: 400 }, cors);
  }

  const initiatorBusy = await env.DB.prepare(
    "SELECT 1 FROM private_session_members m JOIN private_sessions s ON s.id = m.session_id WHERE s.hall_id = ? AND s.status = 'ACTIVE' AND m.player_id = ? LIMIT 1",
  )
    .bind(hall.id, session.playerId)
    .first();

  if (initiatorBusy) {
    return jsonResponse({ error: '你正在私聊中' }, { status: 409 }, cors);
  }

  const target = await env.DB.prepare(
    'SELECT id, name, is_online as isOnline FROM players WHERE hall_id = ? AND name = ? LIMIT 1',
  )
    .bind(hall.id, targetName)
    .first<{ id: string; name: string; isOnline: number }>();

  if (!target) {
    return jsonResponse({ error: '未找到该玩家' }, { status: 404 }, cors);
  }
  if (!target.isOnline) {
    return jsonResponse({ error: '对方不在线' }, { status: 409 }, cors);
  }

  const targetBusy = await env.DB.prepare(
    "SELECT 1 FROM private_session_members m JOIN private_sessions s ON s.id = m.session_id WHERE s.hall_id = ? AND s.status = 'ACTIVE' AND m.player_id = ? LIMIT 1",
  )
    .bind(hall.id, target.id)
    .first();

  if (targetBusy) {
    return jsonResponse({ error: '对方正在私聊中' }, { status: 409 }, cors);
  }

  const now = Date.now();
  const requestId = crypto.randomUUID();
  await env.DB.prepare(
    'INSERT INTO private_requests (id, hall_id, initiator_id, initiator_name, target_id, target_name, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  )
    .bind(requestId, hall.id, session.playerId, session.name, target.id, target.name, 'PENDING', now)
    .run();

  const requestPayload = {
    id: requestId,
    initiatorId: session.playerId,
    initiatorName: session.name,
    targetId: target.id,
    targetName: target.name,
    status: 'PENDING',
    createdAt: now,
  };

  await broadcastToHall(env, hall.id, {
    type: 'private:request',
    request: requestPayload,
    recipients: [session.playerId, target.id],
  });

  return jsonResponse({ request: requestPayload }, {}, cors);
}

async function handleRespondPrivateRequest(
  request: Request,
  env: Env,
  code: string,
  requestId: string,
  cors: CorsOptions,
) {
  const body = await readJson<RespondPrivateRequestBody>(request);
  const response = body.response;
  if (!response) {
    return jsonResponse({ error: '缺少 response' }, { status: 400 }, cors);
  }

  const hall = await env.DB.prepare('SELECT id, day_number as dayNumber, phase FROM halls WHERE code = ? LIMIT 1')
    .bind(code)
    .first<{ id: string; dayNumber: number; phase: string }>();

  if (!hall) {
    return jsonResponse({ error: '大厅不存在' }, { status: 404 }, cors);
  }

  const token = getToken(request);
  const session = await requireSession(env, hall.id, token);
  if (!session) {
    return jsonResponse({ error: '未授权' }, { status: 401 }, cors);
  }

  const requestRow = await env.DB.prepare(
    'SELECT id, initiator_id, initiator_name, target_id, target_name, status, created_at FROM private_requests WHERE id = ? AND hall_id = ? LIMIT 1',
  )
    .bind(requestId, hall.id)
    .first<{
      id: string;
      initiator_id: string;
      initiator_name: string;
      target_id: string;
      target_name: string;
      status: string;
      created_at: number;
    }>();

  if (!requestRow) {
    return jsonResponse({ error: '私聊请求不存在' }, { status: 404 }, cors);
  }

  if (requestRow.target_id !== session.playerId) {
    return jsonResponse({ error: '无权处理该请求' }, { status: 403 }, cors);
  }

  if (requestRow.status !== 'PENDING') {
    return jsonResponse({ error: '该请求已处理' }, { status: 409 }, cors);
  }

  const now = Date.now();
  const nextStatus = response === 'ACCEPT' ? 'ACCEPTED' : 'REJECTED';
  await env.DB.prepare('UPDATE private_requests SET status = ?, responded_at = ? WHERE id = ?')
    .bind(nextStatus, now, requestId)
    .run();

  const requestPayload = {
    id: requestRow.id,
    initiatorId: requestRow.initiator_id,
    initiatorName: requestRow.initiator_name,
    targetId: requestRow.target_id,
    targetName: requestRow.target_name,
    status: nextStatus,
    createdAt: requestRow.created_at,
  };

  let sessionPayload: null | {
    id: string;
    participants: string[];
    status: 'ACTIVE';
    dayNumber: number;
    createdAt: number;
  } = null;

  if (nextStatus === 'ACCEPTED') {
    const sessionId = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO private_sessions (id, hall_id, day_number, status, created_at) VALUES (?, ?, ?, ?, ?)',
    )
      .bind(sessionId, hall.id, hall.dayNumber, 'ACTIVE', now)
      .run();

    await env.DB.prepare(
      'INSERT INTO private_session_members (session_id, player_id, player_name) VALUES (?, ?, ?), (?, ?, ?)',
    )
      .bind(
        sessionId,
        requestRow.initiator_id,
        requestRow.initiator_name,
        sessionId,
        requestRow.target_id,
        requestRow.target_name,
      )
      .run();

    sessionPayload = {
      id: sessionId,
      participants: [requestRow.initiator_name, requestRow.target_name],
      status: 'ACTIVE',
      dayNumber: hall.dayNumber,
      createdAt: now,
    };
  }

  await broadcastToHall(env, hall.id, {
    type: 'private:request-update',
    request: requestPayload,
    recipients: [requestRow.initiator_id, requestRow.target_id],
  });

  if (sessionPayload) {
    await broadcastToHall(env, hall.id, {
      type: 'private:session-start',
      session: sessionPayload,
      recipients: [requestRow.initiator_id, requestRow.target_id],
    });
  }

  return jsonResponse({ request: requestPayload, session: sessionPayload }, {}, cors);
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
  const payload = await verifySessionToken(token, getTokenSecret(env));
  if (!payload || payload.hallId !== hallId) return null;

  const player = await env.DB.prepare('SELECT session_version FROM players WHERE id = ? AND hall_id = ?')
    .bind(payload.playerId, hallId)
    .first<{ session_version: number }>();

  if (!player || player.session_version !== payload.ver) return null;
  return payload;
}

function buildCorsOptions(request: Request, env: Env): CorsOptions {
  return {
    origin: request.headers.get('Origin'),
    allowedOrigins: parseCorsOrigins(env.CORS_ORIGINS),
  };
}

async function broadcastToHall(
  env: Env,
  hallId: string,
  payload: Record<string, unknown> & { type: string; recipients?: string[] },
) {
  const stub = env.HALL_ROOM.get(env.HALL_ROOM.idFromName(hallId));
  await stub.fetch('https://hall-room/broadcast', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

function getTokenSecret(env: Env) {
  return resolveTokenSecret(env.TOKEN_SECRET);
}
