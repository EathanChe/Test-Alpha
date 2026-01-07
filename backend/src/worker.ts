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

type Role = 'PLAYER' | 'STORYTELLER';

type CreateHallBody = {
  name: string;
  password: string;
};

type JoinHallBody = {
  playerName: string;
  password: string;
  storytellerKey?: string;
};

type ResetDayBody = {
  storytellerKey: string;
};

type AdvancePhaseBody = {
  storytellerKey: string;
  action: 'END_DAY' | 'START_DAY';
};

type CreatePrivateRequestBody = {
  targetNames: string[];
};

type RespondPrivateRequestBody = {
  response: 'ACCEPT' | 'REJECT';
};

type DecidePrivateRequestBody = {
  action: 'CANCEL' | 'START_ACCEPTED';
};

type PrivateRequestGroupRow = {
  id: string;
  hall_id: string;
  day_number: number;
  initiator_id: string;
  initiator_name: string;
  status: string;
  created_at: number;
  expires_at: number;
  decided_at: number | null;
};

type PrivateRequestTargetRow = {
  request_id: string;
  target_id: string;
  target_name: string;
  status: string;
  responded_at: number | null;
};

type BulletinEventRow = {
  id: string;
  hall_id: string;
  day_number: number;
  type: string;
  participants: string;
  created_at: number;
};

type RequestTargetPayload = {
  name: string;
  status: string;
  respondedAt: number | null;
};

type RequestPayload = {
  id: string;
  initiatorName: string;
  status: string;
  createdAt: number;
  expiresAt: number;
  dayNumber: number;
  targets: RequestTargetPayload[];
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

    const bulletinMatch = path.match(/^\/api\/halls\/([^/]+)\/bulletins$/);
    if (bulletinMatch && request.method === 'GET') {
      return handleGetBulletins(request, env, bulletinMatch[1], cors);
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

    const privateDecideMatch = path.match(/^\/api\/halls\/([^/]+)\/private-requests\/([^/]+)\/decide$/);
    if (privateDecideMatch && request.method === 'POST') {
      return handleDecidePrivateRequest(request, env, privateDecideMatch[1], privateDecideMatch[2], cors);
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
  const storytellerKey = body.storytellerKey?.trim();
  if (!playerName || !password) {
    return jsonResponse({ error: '缺少昵称或密码' }, { status: 400 }, cors);
  }

  const hall = await env.DB.prepare(
    'SELECT id, name, code, password_hash, password_salt, phase, day_number, storyteller_key FROM halls WHERE code = ? AND status = ? LIMIT 1',
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
    'SELECT id, session_version, role FROM players WHERE hall_id = ? AND name = ? LIMIT 1',
  )
    .bind(hall.id, playerName)
    .first<{ id: string; session_version: number; role: Role }>();

  let role: Role = existingPlayer?.role ?? 'PLAYER';

  if (storytellerKey && storytellerKey === hall.storyteller_key) {
    const existingStoryteller = await env.DB.prepare(
      'SELECT id FROM players WHERE hall_id = ? AND role = ? LIMIT 1',
    )
      .bind(hall.id, 'STORYTELLER')
      .first<{ id: string }>();
    if (existingStoryteller && existingStoryteller.id !== existingPlayer?.id) {
      return jsonResponse({ error: '说书人已被占用' }, { status: 409 }, cors);
    }
    role = 'STORYTELLER';
  }

  let playerId = crypto.randomUUID();
  let sessionVersion = 1;
  let nextRole = role;

  if (existingPlayer) {
    playerId = existingPlayer.id;
    sessionVersion = existingPlayer.session_version + 1;
    nextRole = storytellerKey && storytellerKey === hall.storyteller_key ? 'STORYTELLER' : existingPlayer.role;
    await env.DB.prepare(
      'UPDATE players SET session_version = ?, role = ?, is_online = 1, last_seen_at = ? WHERE id = ?',
    )
      .bind(sessionVersion, nextRole, now, playerId)
      .run();
  } else {
    await env.DB.prepare(
      'INSERT INTO players (id, hall_id, name, role, session_version, is_online, last_seen_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    )
      .bind(playerId, hall.id, playerName, nextRole, sessionVersion, 1, now, now)
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
  const hall = await env.DB.prepare('SELECT id, day_number as dayNumber FROM halls WHERE code = ? AND status = ? LIMIT 1')
    .bind(code, 'active')
    .first<{ id: string; dayNumber: number }>();

  if (!hall) {
    return jsonResponse({ error: '大厅不存在' }, { status: 404 }, cors);
  }

  if (hall.phase === 'NIGHT') {
    return jsonResponse({ error: '黑夜中无法处理私聊请求' }, { status: 403 }, cors);
  }

  const token = getToken(request);
  const session = await requireSession(env, hall.id, token);
  if (!session) {
    return jsonResponse({ error: '未授权' }, { status: 401 }, cors);
  }

  const limit = Math.min(Number(new URL(request.url).searchParams.get('limit') ?? MAX_MESSAGES), 100);
  const result = await env.DB.prepare(
    'SELECT id, hall_id as hallId, player_name as sender, content, created_at as createdAt FROM messages WHERE hall_id = ? AND day_number = ? ORDER BY created_at DESC LIMIT ?',
  )
    .bind(hall.id, hall.dayNumber, limit)
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

  const hallState = await env.DB.prepare('SELECT phase FROM halls WHERE id = ? LIMIT 1')
    .bind(hall.id)
    .first<{ phase: string }>();
  if (hallState?.phase === 'NIGHT') {
    return jsonResponse({ error: '黑夜中无法处理私聊请求' }, { status: 403 }, cors);
  }

  const token = getToken(request);
  const session = await requireSession(env, hall.id, token);
  if (!session) {
    return jsonResponse({ error: '未授权' }, { status: 401 }, cors);
  }

  const players = await fetchRoster(env, hall.id);
  return jsonResponse({ players }, {}, cors);
}

async function handleGetBulletins(request: Request, env: Env, code: string, cors: CorsOptions) {
  const hall = await env.DB.prepare('SELECT id, day_number as dayNumber FROM halls WHERE code = ? AND status = ? LIMIT 1')
    .bind(code, 'active')
    .first<{ id: string; dayNumber: number }>();

  if (!hall) {
    return jsonResponse({ error: '大厅不存在' }, { status: 404 }, cors);
  }

  const token = getToken(request);
  const session = await requireSession(env, hall.id, token);
  if (!session) {
    return jsonResponse({ error: '未授权' }, { status: 401 }, cors);
  }

  const searchParams = new URL(request.url).searchParams;
  const dayParam = searchParams.get('day');

  let rows: BulletinEventRow[] = [];
  if (session.role === 'STORYTELLER' && dayParam === 'all') {
    const result = await env.DB.prepare(
      'SELECT id, hall_id, day_number, type, participants, created_at FROM bulletin_events WHERE hall_id = ? ORDER BY created_at DESC',
    )
      .bind(hall.id)
      .all<BulletinEventRow>();
    rows = result.results;
  } else {
    const dayNumber =
      session.role === 'STORYTELLER' && dayParam && Number.isFinite(Number(dayParam))
        ? Number(dayParam)
        : hall.dayNumber;
    const result = await env.DB.prepare(
      'SELECT id, hall_id, day_number, type, participants, created_at FROM bulletin_events WHERE hall_id = ? AND day_number = ? ORDER BY created_at DESC',
    )
      .bind(hall.id, dayNumber)
      .all<BulletinEventRow>();
    rows = result.results;
  }

  const events = rows.map((row) => ({
    id: row.id,
    hallId: row.hall_id,
    dayNumber: row.day_number,
    type: row.type,
    participants: JSON.parse(row.participants) as string[],
    createdAt: row.created_at,
  }));

  return jsonResponse({ events }, {}, cors);
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
  await env.DB.prepare('DELETE FROM private_request_targets WHERE request_id IN (SELECT id FROM private_request_groups WHERE hall_id = ?)').bind(hall.id).run();
  await env.DB.prepare('DELETE FROM private_request_groups WHERE hall_id = ?').bind(hall.id).run();
  await env.DB.prepare('DELETE FROM private_messages WHERE session_id IN (SELECT id FROM private_sessions WHERE hall_id = ?)').bind(hall.id).run();
  await env.DB.prepare('DELETE FROM private_session_members WHERE session_id IN (SELECT id FROM private_sessions WHERE hall_id = ?)').bind(hall.id).run();
  await env.DB.prepare('DELETE FROM private_sessions WHERE hall_id = ?').bind(hall.id).run();
  await env.DB.prepare('DELETE FROM bulletin_events WHERE hall_id = ?').bind(hall.id).run();

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

    for (const session of activeSessions.results) {
      const members = await env.DB.prepare(
        'SELECT player_id as playerId, player_name as playerName FROM private_session_members WHERE session_id = ?',
      )
        .bind(session.id)
        .all<{ playerId: string; playerName: string }>();
      const participantNames = members.results.map((member) => member.playerName);
      await recordBulletinAndBroadcast(env, hall.id, hall.dayNumber, 'PRIVATE_END', participantNames, now);
      await broadcastToHall(env, hall.id, {
        type: 'private:session-end',
        sessionId: session.id,
        endedByName: 'SYSTEM',
        recipients: members.results.map((member) => member.playerId),
      });
    }

    const pendingGroups = await env.DB.prepare(
      "SELECT id FROM private_request_groups WHERE hall_id = ? AND status IN ('PENDING','DECISION')",
    )
      .bind(hall.id)
      .all<{ id: string }>();

    if (pendingGroups.results.length > 0) {
      const groupIds = pendingGroups.results.map((group) => group.id);
      const placeholders = groupIds.map(() => '?').join(',');
      await env.DB.prepare(
        `UPDATE private_request_targets SET status = 'REJECTED', responded_at = ? WHERE request_id IN (${placeholders}) AND status = 'PENDING'`,
      )
        .bind(now, ...groupIds)
        .run();
      await env.DB.prepare(
        `UPDATE private_request_groups SET status = 'CANCELED', decided_at = ? WHERE id IN (${placeholders})`,
      )
        .bind(now, ...groupIds)
        .run();

      for (const groupId of groupIds) {
        const group = await fetchRequestGroup(env, groupId);
        if (!group) continue;
        const targets = await fetchRequestTargets(env, groupId);
        await broadcastToHall(env, hall.id, {
          type: 'private:request-update',
          request: buildRequestPayload(group, targets),
          recipients: getRequestRecipients(group, targets),
        });
      }
    }

    await broadcastRosterUpdate(env, hall.id);
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

  if (body.action === 'START_DAY') {
    await broadcastToHall(env, hall.id, {
      type: 'system',
      message: '新的一天开始了。',
    });
  }

  return jsonResponse({ hall: updated }, {}, cors);
}

async function handleCreatePrivateRequest(request: Request, env: Env, code: string, cors: CorsOptions) {
  const body = await readJson<CreatePrivateRequestBody>(request);
  const targetNames = Array.from(
    new Set((body.targetNames ?? []).map((name) => name.trim()).filter(Boolean)),
  );
  if (targetNames.length === 0) {
    return jsonResponse({ error: '请选择至少一名玩家' }, { status: 400 }, cors);
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

  const initiatorBusy = await env.DB.prepare(
    "SELECT 1 FROM private_session_members m JOIN private_sessions s ON s.id = m.session_id WHERE s.hall_id = ? AND s.status = 'ACTIVE' AND m.player_id = ? LIMIT 1",
  )
    .bind(hall.id, session.playerId)
    .first();

  if (initiatorBusy) {
    return jsonResponse({ error: '你正在私聊中' }, { status: 409 }, cors);
  }

  if (targetNames.includes(session.name)) {
    return jsonResponse({ error: '不能邀请自己' }, { status: 400 }, cors);
  }

  const placeholders = targetNames.map(() => '?').join(',');
  const targetsResult = await env.DB.prepare(
    `SELECT id, name, is_online as isOnline, role FROM players WHERE hall_id = ? AND name IN (${placeholders})`,
  )
    .bind(hall.id, ...targetNames)
    .all<{ id: string; name: string; isOnline: number; role: Role }>();

  if (targetsResult.results.length !== targetNames.length) {
    return jsonResponse({ error: '部分玩家不存在' }, { status: 404 }, cors);
  }

  const storytellerTarget = targetsResult.results.find((target) => target.role === 'STORYTELLER');
  if (storytellerTarget) {
    return jsonResponse({ error: '不能邀请说书人' }, { status: 400 }, cors);
  }

  const offlineTarget = targetsResult.results.find((target) => target.isOnline !== 1);
  if (offlineTarget) {
    return jsonResponse({ error: '有玩家不在线' }, { status: 409 }, cors);
  }

  const targetIds = targetsResult.results.map((target) => target.id);
  const busyResult = await env.DB.prepare(
    `SELECT m.player_id as playerId
     FROM private_session_members m
     JOIN private_sessions s ON s.id = m.session_id
     WHERE s.hall_id = ? AND s.status = 'ACTIVE' AND m.player_id IN (${targetIds
       .map(() => '?')
       .join(',')})`,
  )
    .bind(hall.id, ...targetIds)
    .all<{ playerId: string }>();

  if (busyResult.results.length > 0) {
    return jsonResponse({ error: '有玩家正在私聊中' }, { status: 409 }, cors);
  }

  const now = Date.now();
  const requestId = crypto.randomUUID();
  const expiresAt = now + 30_000;

  await env.DB.prepare(
    'INSERT INTO private_request_groups (id, hall_id, day_number, initiator_id, initiator_name, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  )
    .bind(requestId, hall.id, hall.dayNumber, session.playerId, session.name, 'PENDING', now, expiresAt)
    .run();

  const values = targetsResult.results.map(() => '(?, ?, ?, ?, ?)').join(',');
  const bindings = targetsResult.results.flatMap((target) => [
    requestId,
    target.id,
    target.name,
    'PENDING',
    null,
  ]);
  await env.DB.prepare(
    `INSERT INTO private_request_targets (request_id, target_id, target_name, status, responded_at) VALUES ${values}`,
  )
    .bind(...bindings)
    .run();

  const groupRow: PrivateRequestGroupRow = {
    id: requestId,
    hall_id: hall.id,
    day_number: hall.dayNumber,
    initiator_id: session.playerId,
    initiator_name: session.name,
    status: 'PENDING',
    created_at: now,
    expires_at: expiresAt,
    decided_at: null,
  };
  const targets: PrivateRequestTargetRow[] = targetsResult.results.map((target) => ({
    request_id: requestId,
    target_id: target.id,
    target_name: target.name,
    status: 'PENDING',
    responded_at: null,
  }));

  const requestPayload = buildRequestPayload(groupRow, targets);
  await broadcastToHall(env, hall.id, {
    type: 'private:request',
    request: requestPayload,
    recipients: getRequestRecipients(groupRow, targets),
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

  const group = await fetchRequestGroup(env, requestId);
  if (!group || group.hall_id !== hall.id) {
    return jsonResponse({ error: '私聊请求不存在' }, { status: 404 }, cors);
  }

  if (group.status !== 'PENDING') {
    return jsonResponse({ error: '该请求已处理' }, { status: 409 }, cors);
  }

  const targetRow = await env.DB.prepare(
    'SELECT status FROM private_request_targets WHERE request_id = ? AND target_id = ? LIMIT 1',
  )
    .bind(requestId, session.playerId)
    .first<{ status: string }>();

  if (!targetRow) {
    return jsonResponse({ error: '无权处理该请求' }, { status: 403 }, cors);
  }

  const now = Date.now();
  if (group.expires_at <= now) {
    await env.DB.prepare(
      "UPDATE private_request_targets SET status = 'TIMEOUT', responded_at = ? WHERE request_id = ? AND status = 'PENDING'",
    )
      .bind(now, requestId)
      .run();
    await env.DB.prepare(
      "UPDATE private_request_groups SET status = 'DECISION', decided_at = ? WHERE id = ? AND status = 'PENDING'",
    )
      .bind(now, requestId)
      .run();

    const updatedGroup = await fetchRequestGroup(env, requestId);
    const targets = await fetchRequestTargets(env, requestId);
    if (updatedGroup) {
      await broadcastToHall(env, hall.id, {
        type: 'private:request-update',
        request: buildRequestPayload(updatedGroup, targets),
        recipients: getRequestRecipients(updatedGroup, targets),
      });
    }
    return jsonResponse({ error: '请求已超时' }, { status: 409 }, cors);
  }

  if (targetRow.status !== 'PENDING') {
    return jsonResponse({ error: '该请求已处理' }, { status: 409 }, cors);
  }

  let nextStatus = response === 'ACCEPT' ? 'ACCEPTED' : 'REJECTED';
  if (nextStatus === 'ACCEPTED') {
    const busy = await isPlayerInActiveSession(env, hall.id, session.playerId);
    if (busy) {
      nextStatus = 'REJECTED';
    }
  }
  await env.DB.prepare('UPDATE private_request_targets SET status = ?, responded_at = ? WHERE request_id = ? AND target_id = ?')
    .bind(nextStatus, now, requestId, session.playerId)
    .run();

  const targets = await fetchRequestTargets(env, requestId);
  const pendingTargets = targets.filter((target) => target.status === 'PENDING');
  const allAccepted = targets.every((target) => target.status === 'ACCEPTED');
  const hasRejection = targets.some((target) => target.status === 'REJECTED' || target.status === 'TIMEOUT');

  let groupStatus = group.status;
  let sessionPayload: null | {
    id: string;
    participants: string[];
    status: 'ACTIVE';
    dayNumber: number;
    createdAt: number;
  } = null;

  if (allAccepted) {
    const participants = [
      { id: group.initiator_id, name: group.initiator_name },
      ...targets.map((target) => ({ id: target.target_id, name: target.target_name })),
    ];
    sessionPayload = await createPrivateSession(env, hall.id, hall.dayNumber, participants, now);
    groupStatus = 'COMPLETED';
  } else if (pendingTargets.length === 0 && hasRejection) {
    groupStatus = 'DECISION';
  }

  if (groupStatus !== group.status) {
    await env.DB.prepare('UPDATE private_request_groups SET status = ?, decided_at = ? WHERE id = ?')
      .bind(groupStatus, groupStatus === 'PENDING' ? null : now, requestId)
      .run();
  }

  const updatedGroup = await fetchRequestGroup(env, requestId);
  const updatedTargets = await fetchRequestTargets(env, requestId);
  if (updatedGroup) {
    await broadcastToHall(env, hall.id, {
      type: 'private:request-update',
      request: buildRequestPayload(updatedGroup, updatedTargets),
      recipients: getRequestRecipients(updatedGroup, updatedTargets),
    });
  }

  if (sessionPayload) {
    await broadcastToHall(env, hall.id, {
      type: 'private:session-start',
      session: sessionPayload,
      recipients: [
        group.initiator_id,
        ...targets.map((target) => target.target_id),
      ],
    });
    await broadcastRosterUpdate(env, hall.id);
  }

  return jsonResponse({ request: updatedGroup ? buildRequestPayload(updatedGroup, updatedTargets) : null, session: sessionPayload }, {}, cors);
}

async function handleDecidePrivateRequest(
  request: Request,
  env: Env,
  code: string,
  requestId: string,
  cors: CorsOptions,
) {
  const body = await readJson<DecidePrivateRequestBody>(request);
  const action = body.action;
  if (!action) {
    return jsonResponse({ error: '缺少 action' }, { status: 400 }, cors);
  }

  const hall = await env.DB.prepare('SELECT id, day_number as dayNumber, phase FROM halls WHERE code = ? LIMIT 1')
    .bind(code)
    .first<{ id: string; dayNumber: number; phase: string }>();

  if (!hall) {
    return jsonResponse({ error: '大厅不存在' }, { status: 404 }, cors);
  }

  if (hall.phase === 'NIGHT') {
    return jsonResponse({ error: '黑夜中无法处理私聊请求' }, { status: 403 }, cors);
  }

  const token = getToken(request);
  const session = await requireSession(env, hall.id, token);
  if (!session) {
    return jsonResponse({ error: '未授权' }, { status: 401 }, cors);
  }

  const group = await fetchRequestGroup(env, requestId);
  if (!group || group.hall_id !== hall.id) {
    return jsonResponse({ error: '私聊请求不存在' }, { status: 404 }, cors);
  }

  if (group.initiator_id !== session.playerId) {
    return jsonResponse({ error: '无权处理该请求' }, { status: 403 }, cors);
  }

  if (group.status !== 'DECISION') {
    return jsonResponse({ error: '该请求不需要决策' }, { status: 409 }, cors);
  }

  const targets = await fetchRequestTargets(env, requestId);
  const now = Date.now();

  if (action === 'CANCEL') {
    await env.DB.prepare("UPDATE private_request_groups SET status = 'CANCELED', decided_at = ? WHERE id = ?")
      .bind(now, requestId)
      .run();
    const updatedGroup = await fetchRequestGroup(env, requestId);
    if (updatedGroup) {
      await broadcastToHall(env, hall.id, {
        type: 'private:request-update',
        request: buildRequestPayload(updatedGroup, targets),
        recipients: getRequestRecipients(updatedGroup, targets),
      });
    }
    return jsonResponse({ request: updatedGroup ? buildRequestPayload(updatedGroup, targets) : null }, {}, cors);
  }

  const acceptedTargets = targets.filter((target) => target.status === 'ACCEPTED');
  if (acceptedTargets.length === 0) {
    return jsonResponse({ error: '没有同意的玩家' }, { status: 409 }, cors);
  }

  if (await isPlayerInActiveSession(env, hall.id, group.initiator_id)) {
    return jsonResponse({ error: '你正在私聊中' }, { status: 409 }, cors);
  }

  for (const target of acceptedTargets) {
    if (await isPlayerInActiveSession(env, hall.id, target.target_id)) {
      return jsonResponse({ error: '有玩家正在私聊中' }, { status: 409 }, cors);
    }
  }

  const participants = [
    { id: group.initiator_id, name: group.initiator_name },
    ...acceptedTargets.map((target) => ({ id: target.target_id, name: target.target_name })),
  ];
  const sessionPayload = await createPrivateSession(env, hall.id, hall.dayNumber, participants, now);

  await env.DB.prepare("UPDATE private_request_groups SET status = 'COMPLETED', decided_at = ? WHERE id = ?")
    .bind(now, requestId)
    .run();

  const updatedGroup = await fetchRequestGroup(env, requestId);
  if (updatedGroup) {
    await broadcastToHall(env, hall.id, {
      type: 'private:request-update',
      request: buildRequestPayload(updatedGroup, targets),
      recipients: getRequestRecipients(updatedGroup, targets),
    });
  }
  await broadcastToHall(env, hall.id, {
    type: 'private:session-start',
    session: sessionPayload,
    recipients: participants.map((participant) => participant.id),
  });
  await broadcastRosterUpdate(env, hall.id);

  return jsonResponse({ request: updatedGroup ? buildRequestPayload(updatedGroup, targets) : null, session: sessionPayload }, {}, cors);
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

  const player = await env.DB.prepare(
    'SELECT session_version, role, name FROM players WHERE id = ? AND hall_id = ?',
  )
    .bind(payload.playerId, hallId)
    .first<{ session_version: number; role: Role; name: string }>();

  if (!player || player.session_version !== payload.ver) return null;
  return { ...payload, role: player.role, name: player.name };
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

async function fetchRoster(env: Env, hallId: string) {
  const result = await env.DB.prepare(
    `SELECT
      p.name as name,
      p.is_online as isOnline,
      p.role as role,
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
    .bind(hallId)
    .all<{ name: string; isOnline: number; role: Role; inPrivate: number }>();

  return result.results.map((row) => ({
    name: row.name,
    isOnline: row.isOnline === 1,
    role: row.role,
    inPrivate: row.inPrivate === 1,
  }));
}

async function fetchRequestGroup(env: Env, requestId: string) {
  return await env.DB.prepare(
    `SELECT
      id,
      hall_id,
      day_number,
      initiator_id,
      initiator_name,
      status,
      created_at,
      expires_at,
      decided_at
    FROM private_request_groups
    WHERE id = ?
    LIMIT 1`,
  )
    .bind(requestId)
    .first<PrivateRequestGroupRow>();
}

async function fetchRequestTargets(env: Env, requestId: string) {
  const result = await env.DB.prepare(
    `SELECT
      request_id,
      target_id,
      target_name,
      status,
      responded_at
    FROM private_request_targets
    WHERE request_id = ?
    ORDER BY target_name`,
  )
    .bind(requestId)
    .all<PrivateRequestTargetRow>();

  return result.results;
}

function buildRequestPayload(group: PrivateRequestGroupRow, targets: PrivateRequestTargetRow[]): RequestPayload {
  return {
    id: group.id,
    initiatorName: group.initiator_name,
    status: group.status,
    createdAt: group.created_at,
    expiresAt: group.expires_at,
    dayNumber: group.day_number,
    targets: targets.map((target) => ({
      name: target.target_name,
      status: target.status,
      respondedAt: target.responded_at ?? null,
    })),
  };
}

function getRequestRecipients(group: PrivateRequestGroupRow, targets: PrivateRequestTargetRow[]) {
  const recipients = new Set<string>([group.initiator_id]);
  targets.forEach((target) => recipients.add(target.target_id));
  return Array.from(recipients);
}

async function createBulletinEvent(
  env: Env,
  hallId: string,
  dayNumber: number,
  type: 'PRIVATE_START' | 'PRIVATE_END',
  participants: string[],
  createdAt: number,
) {
  const eventId = crypto.randomUUID();
  await env.DB.prepare(
    'INSERT INTO bulletin_events (id, hall_id, day_number, type, participants, created_at) VALUES (?, ?, ?, ?, ?, ?)',
  )
    .bind(eventId, hallId, dayNumber, type, JSON.stringify(participants), createdAt)
    .run();

  return {
    id: eventId,
    hallId,
    dayNumber,
    type,
    participants,
    createdAt,
  };
}

async function recordBulletinAndBroadcast(
  env: Env,
  hallId: string,
  dayNumber: number,
  type: 'PRIVATE_START' | 'PRIVATE_END',
  participants: string[],
  createdAt: number,
) {
  const event = await createBulletinEvent(env, hallId, dayNumber, type, participants, createdAt);
  await broadcastToHall(env, hallId, { type: 'bulletin:new', event });
  return event;
}

async function createPrivateSession(
  env: Env,
  hallId: string,
  dayNumber: number,
  participants: { id: string; name: string }[],
  createdAt: number,
) {
  const sessionId = crypto.randomUUID();
  await env.DB.prepare(
    'INSERT INTO private_sessions (id, hall_id, day_number, status, created_at) VALUES (?, ?, ?, ?, ?)',
  )
    .bind(sessionId, hallId, dayNumber, 'ACTIVE', createdAt)
    .run();

  const values = participants.map(() => '(?, ?, ?)').join(',');
  const bindings = participants.flatMap((participant) => [sessionId, participant.id, participant.name]);
  await env.DB.prepare(
    `INSERT INTO private_session_members (session_id, player_id, player_name) VALUES ${values}`,
  )
    .bind(...bindings)
    .run();

  const participantNames = participants.map((participant) => participant.name);
  await recordBulletinAndBroadcast(env, hallId, dayNumber, 'PRIVATE_START', participantNames, createdAt);

  return {
    id: sessionId,
    participants: participantNames,
    status: 'ACTIVE' as const,
    dayNumber,
    createdAt,
  };
}

async function broadcastRosterUpdate(env: Env, hallId: string) {
  const roster = await fetchRoster(env, hallId);
  await broadcastToHall(env, hallId, { type: 'presence:update', roster });
}

async function isPlayerInActiveSession(env: Env, hallId: string, playerId: string) {
  const row = await env.DB.prepare(
    "SELECT 1 FROM private_session_members m JOIN private_sessions s ON s.id = m.session_id WHERE s.hall_id = ? AND s.status = 'ACTIVE' AND m.player_id = ? LIMIT 1",
  )
    .bind(hallId, playerId)
    .first<{ '1': number }>();
  return Boolean(row);
}
