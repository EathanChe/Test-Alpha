var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/utils.ts
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var DEFAULT_TOKEN_SECRET = "dev-token-secret";
function base64UrlEncode(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
__name(base64UrlEncode, "base64UrlEncode");
function base64UrlDecode(data) {
  const padded = data.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(data.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
__name(base64UrlDecode, "base64UrlDecode");
var DEFAULT_CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"];
function parseCorsOrigins(raw) {
  if (!raw) return DEFAULT_CORS_ORIGINS;
  const origins = raw.split(",").map((value) => value.trim()).filter(Boolean);
  return origins.length > 0 ? origins : DEFAULT_CORS_ORIGINS;
}
__name(parseCorsOrigins, "parseCorsOrigins");
function resolveCorsOrigin(requestOrigin, allowedOrigins) {
  if (allowedOrigins.includes("*")) {
    return "*";
  }
  if (requestOrigin && allowedOrigins.includes(requestOrigin)) {
    return requestOrigin;
  }
  return allowedOrigins[0] ?? "";
}
__name(resolveCorsOrigin, "resolveCorsOrigin");
function corsHeaders(options = {}, init) {
  const headers = new Headers(init);
  const allowedOrigins = options.allowedOrigins ?? DEFAULT_CORS_ORIGINS;
  const resolvedOrigin = resolveCorsOrigin(options.origin ?? null, allowedOrigins);
  if (resolvedOrigin) {
    headers.set("Access-Control-Allow-Origin", resolvedOrigin);
    if (resolvedOrigin !== "*") {
      headers.set("Vary", "Origin");
    }
  }
  headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  return headers;
}
__name(corsHeaders, "corsHeaders");
function jsonResponse(payload, init = {}, cors) {
  const headers = corsHeaders(cors, init.headers);
  headers.set("Content-Type", "application/json");
  const status = init.status ?? 200;
  if (status === 204 || status === 205 || status === 304) {
    return new Response(null, { ...init, status, headers });
  }
  return new Response(JSON.stringify(payload), { ...init, status, headers });
}
__name(jsonResponse, "jsonResponse");
async function readJson(request) {
  const body = await request.json();
  return body;
}
__name(readJson, "readJson");
async function hashPassword(password, salt) {
  const resolvedSalt = salt ?? base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: encoder.encode(resolvedSalt),
      iterations: 1e5,
      hash: "SHA-256"
    },
    key,
    256
  );
  return { hash: base64UrlEncode(bits), salt: resolvedSalt };
}
__name(hashPassword, "hashPassword");
async function verifyPassword(password, salt, hash) {
  const result = await hashPassword(password, salt);
  return result.hash === hash;
}
__name(verifyPassword, "verifyPassword");
async function createSessionToken(payload, secret) {
  const data = encoder.encode(JSON.stringify(payload));
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, data);
  return `${base64UrlEncode(data)}.${base64UrlEncode(signature)}`;
}
__name(createSessionToken, "createSessionToken");
async function verifySessionToken(token, secret) {
  const [payloadPart, signaturePart] = token.split(".");
  if (!payloadPart || !signaturePart) return null;
  const payloadBytes = base64UrlDecode(payloadPart);
  const signatureBytes = base64UrlDecode(signaturePart);
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const ok = await crypto.subtle.verify("HMAC", key, signatureBytes, payloadBytes);
  if (!ok) return null;
  const payload = JSON.parse(decoder.decode(payloadBytes));
  if (payload.exp && Date.now() > payload.exp) return null;
  return payload;
}
__name(verifySessionToken, "verifySessionToken");
function randomHallCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let i = 0; i < 6; i += 1) {
    code += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return code;
}
__name(randomHallCode, "randomHallCode");
function resolveTokenSecret(secret) {
  const trimmed = secret?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : DEFAULT_TOKEN_SECRET;
}
__name(resolveTokenSecret, "resolveTokenSecret");

// src/hallRoom.ts
var HallRoom = class {
  static {
    __name(this, "HallRoom");
  }
  state;
  env;
  connections = /* @__PURE__ */ new Map();
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }
  async fetch(request) {
    if (request.method === "POST" && new URL(request.url).pathname.endsWith("/broadcast")) {
      const payload = await request.json();
      this.broadcastToHall(payload);
      return jsonResponse({ ok: true });
    }
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected WebSocket", { status: 426 });
    }
    const hallId = request.headers.get("X-Hall-Id");
    const token = request.headers.get("X-Session-Token");
    if (!hallId || !token) {
      return new Response("Missing auth headers", { status: 400 });
    }
    const session = await verifySessionToken(token, resolveTokenSecret(this.env.TOKEN_SECRET));
    if (!session || session.hallId !== hallId) {
      return new Response("Unauthorized", { status: 401 });
    }
    const playerRow = await this.env.DB.prepare(
      "SELECT session_version, name FROM players WHERE id = ? AND hall_id = ?"
    ).bind(session.playerId, hallId).first();
    if (!playerRow || playerRow.session_version !== session.ver) {
      return new Response("Unauthorized", { status: 401 });
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.disconnectOtherSessions(session.playerId);
    server.accept();
    this.connections.set(server, {
      hallId,
      playerId: session.playerId,
      playerName: session.name
    });
    server.addEventListener("message", (event) => {
      this.handleMessage(server, event).catch((error) => {
        console.error("WS message error", error);
      });
    });
    server.addEventListener("close", () => {
      this.handleClose(server).catch((error) => {
        console.error("WS close error", error);
      });
    });
    server.addEventListener("error", () => {
      this.handleClose(server).catch((error) => {
        console.error("WS error", error);
      });
    });
    await this.markOnline(session.playerId);
    await this.sendInit(server, hallId, session.playerId);
    await this.broadcastPresence(hallId);
    return new Response(null, { status: 101, webSocket: client });
  }
  disconnectOtherSessions(playerId) {
    const socketsToClose = [];
    this.connections.forEach((info, ws) => {
      if (info.playerId === playerId) {
        socketsToClose.push(ws);
      }
    });
    socketsToClose.forEach((ws) => {
      ws.close(4001, "Session replaced");
      this.connections.delete(ws);
    });
  }
  async markOnline(playerId) {
    const now = Date.now();
    await this.env.DB.prepare("UPDATE players SET is_online = 1, last_seen_at = ? WHERE id = ?").bind(now, playerId).run();
  }
  async markOfflineIfIdle(playerId) {
    const stillConnected = Array.from(this.connections.values()).some((info) => info.playerId === playerId);
    if (stillConnected) return;
    const now = Date.now();
    await this.env.DB.prepare("UPDATE players SET is_online = 0, last_seen_at = ? WHERE id = ?").bind(now, playerId).run();
  }
  async sendInit(ws, hallId, playerId) {
    const messages = await this.fetchRecentMessages(hallId, 50);
    const roster = await this.fetchRoster(hallId);
    const hall = await this.fetchHall(hallId);
    const privateRequests = await this.fetchPrivateRequests(hallId, playerId);
    const privateSessions = await this.fetchPrivateSessions(hallId, playerId);
    const privateMessages = await this.fetchPrivateMessages(privateSessions);
    const payload = {
      type: "init",
      messages,
      roster,
      hall,
      privateRequests,
      privateSessions,
      privateMessages
    };
    ws.send(JSON.stringify(payload));
  }
  async fetchHall(hallId) {
    return await this.env.DB.prepare(
      "SELECT id, code, name, day_number as dayNumber, phase FROM halls WHERE id = ? LIMIT 1"
    ).bind(hallId).first();
  }
  async fetchRecentMessages(hallId, limit) {
    const result = await this.env.DB.prepare(
      "SELECT id, hall_id as hallId, player_name as sender, content, created_at as createdAt FROM messages WHERE hall_id = ? ORDER BY created_at DESC LIMIT ?"
    ).bind(hallId, limit).all();
    return result.results.reverse();
  }
  async fetchRoster(hallId) {
    const result = await this.env.DB.prepare(
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
      ORDER BY p.created_at`
    ).bind(hallId).all();
    return result.results.map((row) => ({
      name: row.name,
      isOnline: row.isOnline === 1,
      inPrivate: row.inPrivate === 1
    }));
  }
  async fetchPrivateRequests(hallId, playerId) {
    const result = await this.env.DB.prepare(
      `SELECT
        id,
        initiator_id as initiatorId,
        initiator_name as initiatorName,
        target_id as targetId,
        target_name as targetName,
        status,
        created_at as createdAt
      FROM private_requests
      WHERE hall_id = ? AND status = 'PENDING' AND (target_id = ? OR initiator_id = ?)
      ORDER BY created_at DESC`
    ).bind(hallId, playerId, playerId).all();
    return result.results;
  }
  async fetchPrivateSessions(hallId, playerId) {
    const result = await this.env.DB.prepare(
      `SELECT
        s.id as id,
        s.day_number as dayNumber,
        s.status as status,
        s.created_at as createdAt,
        s.ended_at as endedAt,
        s.ended_by_name as endedByName
      FROM private_sessions s
      JOIN private_session_members m ON m.session_id = s.id
      WHERE s.hall_id = ? AND m.player_id = ?
      ORDER BY s.created_at DESC`
    ).bind(hallId, playerId).all();
    const sessions = [];
    for (const row of result.results) {
      const members = await this.env.DB.prepare(
        "SELECT player_name as playerName FROM private_session_members WHERE session_id = ? ORDER BY player_name"
      ).bind(row.id).all();
      sessions.push({
        ...row,
        participants: members.results.map((member) => member.playerName),
        status: row.status,
        endedAt: row.endedAt ?? null,
        endedByName: row.endedByName ?? null
      });
    }
    return sessions;
  }
  async fetchPrivateMessages(sessions) {
    const result = {};
    for (const session of sessions) {
      const messages = await this.env.DB.prepare(
        "SELECT id, session_id as sessionId, sender_name as sender, content, created_at as createdAt FROM private_messages WHERE session_id = ? ORDER BY created_at ASC"
      ).bind(session.id).all();
      result[session.id] = messages.results;
    }
    return result;
  }
  async broadcastPresence(hallId) {
    const roster = await this.fetchRoster(hallId);
    const payload = { type: "presence:update", roster };
    this.broadcastToHall(payload, hallId);
  }
  broadcastToHall(payload, hallId) {
    const { recipients, ...message } = payload;
    const data = JSON.stringify(message);
    this.connections.forEach((info, ws) => {
      if (hallId && info.hallId !== hallId) return;
      if (recipients && !recipients.includes(info.playerId)) return;
      try {
        ws.send(data);
      } catch (error) {
        console.error("WS send error", error);
      }
    });
  }
  async ensureDay(ws, hallId) {
    const hall = await this.fetchHall(hallId);
    if (hall?.phase === "NIGHT") {
      ws.send(JSON.stringify({ type: "system", message: "\u9ED1\u591C\u4E2D\u65E0\u6CD5\u6267\u884C\u8BE5\u64CD\u4F5C\u3002" }));
      return false;
    }
    return true;
  }
  async handleMessage(ws, event) {
    const info = this.connections.get(ws);
    if (!info) return;
    let payload = null;
    try {
      payload = JSON.parse(typeof event.data === "string" ? event.data : "");
    } catch {
      payload = null;
    }
    if (!payload) return;
    if (payload.type === "ping") {
      ws.send(JSON.stringify({ type: "pong" }));
      return;
    }
    if (payload.type === "chat:send") {
      const content = (payload.content ?? "").trim();
      if (!content) return;
      if (!await this.ensureDay(ws, info.hallId)) return;
      const message = {
        id: crypto.randomUUID(),
        hallId: info.hallId,
        sender: info.playerName,
        content,
        createdAt: Date.now()
      };
      await this.env.DB.prepare(
        "INSERT INTO messages (id, hall_id, player_id, player_name, content, created_at) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(message.id, info.hallId, info.playerId, info.playerName, message.content, message.createdAt).run();
      this.broadcastToHall({ type: "chat:new", message }, info.hallId);
      return;
    }
    if (payload.type === "private:send") {
      const sessionId = payload.sessionId?.trim();
      const content = (payload.content ?? "").trim();
      if (!sessionId || !content) return;
      if (!await this.ensureDay(ws, info.hallId)) return;
      const members = await this.fetchSessionMembers(sessionId);
      if (!members.some((member) => member.playerId === info.playerId)) return;
      const message = {
        id: crypto.randomUUID(),
        sessionId,
        sender: info.playerName,
        content,
        createdAt: Date.now()
      };
      await this.env.DB.prepare(
        "INSERT INTO private_messages (id, session_id, sender_id, sender_name, content, created_at) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(message.id, sessionId, info.playerId, info.playerName, message.content, message.createdAt).run();
      this.broadcastToHall(
        { type: "private:message", message, recipients: members.map((member) => member.playerId) },
        info.hallId
      );
      return;
    }
    if (payload.type === "private:end") {
      const sessionId = payload.sessionId?.trim();
      if (!sessionId) return;
      const members = await this.fetchSessionMembers(sessionId);
      if (!members.some((member) => member.playerId === info.playerId)) return;
      const now = Date.now();
      await this.env.DB.prepare(
        "UPDATE private_sessions SET status = ?, ended_at = ?, ended_by_name = ? WHERE id = ?"
      ).bind("ENDED", now, info.playerName, sessionId).run();
      this.broadcastToHall(
        {
          type: "private:session-end",
          sessionId,
          endedByName: info.playerName,
          recipients: members.map((member) => member.playerId)
        },
        info.hallId
      );
    }
  }
  async fetchSessionMembers(sessionId) {
    const result = await this.env.DB.prepare(
      "SELECT player_id as playerId, player_name as playerName FROM private_session_members WHERE session_id = ?"
    ).bind(sessionId).all();
    return result.results;
  }
  async handleClose(ws) {
    const info = this.connections.get(ws);
    if (!info) return;
    this.connections.delete(ws);
    await this.markOfflineIfIdle(info.playerId);
    await this.broadcastPresence(info.hallId);
  }
};

// src/worker.ts
var MAX_MESSAGES = 50;
var SESSION_TTL_MS = 1e3 * 60 * 60 * 24 * 7;
var worker_default = {
  async fetch(request, env) {
    const cors = buildCorsOptions(request, env);
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(cors)
      });
    }
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === "/api/halls" && request.method === "POST") {
      return handleCreateHall(request, env, cors);
    }
    if (path === "/api/halls" && request.method === "GET") {
      return handleListHalls(env, cors);
    }
    const joinMatch = path.match(/^\/api\/halls\/([^/]+)\/join$/);
    if (joinMatch && request.method === "POST") {
      return handleJoinHall(request, env, joinMatch[1], cors);
    }
    const hallMatch = path.match(/^\/api\/halls\/([^/]+)$/);
    if (hallMatch && request.method === "GET") {
      return handleGetHall(env, hallMatch[1], cors);
    }
    const messagesMatch = path.match(/^\/api\/halls\/([^/]+)\/messages$/);
    if (messagesMatch && request.method === "GET") {
      return handleGetMessages(request, env, messagesMatch[1], cors);
    }
    const rosterMatch = path.match(/^\/api\/halls\/([^/]+)\/roster$/);
    if (rosterMatch && request.method === "GET") {
      return handleGetRoster(request, env, rosterMatch[1], cors);
    }
    const resetMatch = path.match(/^\/api\/halls\/([^/]+)\/admin\/reset-day$/);
    if (resetMatch && request.method === "POST") {
      return handleResetDay(request, env, resetMatch[1], cors);
    }
    const phaseMatch = path.match(/^\/api\/halls\/([^/]+)\/admin\/phase$/);
    if (phaseMatch && request.method === "POST") {
      return handleAdvancePhase(request, env, phaseMatch[1], cors);
    }
    const privateRequestMatch = path.match(/^\/api\/halls\/([^/]+)\/private-requests$/);
    if (privateRequestMatch && request.method === "POST") {
      return handleCreatePrivateRequest(request, env, privateRequestMatch[1], cors);
    }
    const privateRespondMatch = path.match(/^\/api\/halls\/([^/]+)\/private-requests\/([^/]+)\/respond$/);
    if (privateRespondMatch && request.method === "POST") {
      return handleRespondPrivateRequest(request, env, privateRespondMatch[1], privateRespondMatch[2], cors);
    }
    const wsMatch = path.match(/^\/ws\/halls\/([^/]+)$/);
    if (wsMatch) {
      return handleWebSocket(request, env, wsMatch[1]);
    }
    return jsonResponse({ error: "Not found" }, { status: 404 }, cors);
  }
};
async function handleCreateHall(request, env, cors) {
  const body = await readJson(request);
  const name = body.name?.trim();
  const password = body.password?.trim();
  if (!name || !password) {
    return jsonResponse({ error: "\u7F3A\u5C11\u5927\u5385\u540D\u79F0\u6216\u5BC6\u7801" }, { status: 400 }, cors);
  }
  const { hash, salt } = await hashPassword(password);
  const hallId = crypto.randomUUID();
  const hallCode = await generateUniqueHallCode(env);
  const storytellerKey = crypto.randomUUID();
  const now = Date.now();
  await env.DB.prepare(
    "INSERT INTO halls (id, code, name, password_hash, password_salt, phase, day_number, status, storyteller_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(hallId, hallCode, name, hash, salt, "DAY", 1, "active", storytellerKey, now, now).run();
  return jsonResponse({ hallId, hallCode, storytellerKey }, {}, cors);
}
__name(handleCreateHall, "handleCreateHall");
async function handleListHalls(env, cors) {
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
    ORDER BY h.created_at DESC`
  ).all();
  return jsonResponse({ halls: result.results }, {}, cors);
}
__name(handleListHalls, "handleListHalls");
async function handleJoinHall(request, env, code, cors) {
  const body = await readJson(request);
  const playerName = body.playerName?.trim();
  const password = body.password?.trim();
  if (!playerName || !password) {
    return jsonResponse({ error: "\u7F3A\u5C11\u6635\u79F0\u6216\u5BC6\u7801" }, { status: 400 }, cors);
  }
  const hall = await env.DB.prepare(
    "SELECT id, name, code, password_hash, password_salt, phase, day_number FROM halls WHERE code = ? AND status = ? LIMIT 1"
  ).bind(code, "active").first();
  if (!hall) {
    return jsonResponse({ error: "\u5927\u5385\u4E0D\u5B58\u5728" }, { status: 404 }, cors);
  }
  const passwordOk = await verifyPassword(password, hall.password_salt, hall.password_hash);
  if (!passwordOk) {
    return jsonResponse({ error: "\u5BC6\u7801\u4E0D\u6B63\u786E" }, { status: 401 }, cors);
  }
  const now = Date.now();
  const existingPlayer = await env.DB.prepare(
    "SELECT id, session_version FROM players WHERE hall_id = ? AND name = ? LIMIT 1"
  ).bind(hall.id, playerName).first();
  let playerId = crypto.randomUUID();
  let sessionVersion = 1;
  if (existingPlayer) {
    playerId = existingPlayer.id;
    sessionVersion = existingPlayer.session_version + 1;
    await env.DB.prepare(
      "UPDATE players SET session_version = ?, is_online = 1, last_seen_at = ? WHERE id = ?"
    ).bind(sessionVersion, now, playerId).run();
  } else {
    await env.DB.prepare(
      "INSERT INTO players (id, hall_id, name, session_version, is_online, last_seen_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).bind(playerId, hall.id, playerName, sessionVersion, 1, now, now).run();
  }
  const sessionToken = await createSessionToken(
    {
      playerId,
      hallId: hall.id,
      name: playerName,
      ver: sessionVersion,
      exp: now + SESSION_TTL_MS
    },
    getTokenSecret(env)
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
        phase: hall.phase
      }
    },
    void 0,
    cors
  );
}
__name(handleJoinHall, "handleJoinHall");
async function handleGetHall(env, code, cors) {
  const hall = await env.DB.prepare(
    "SELECT id, code, name, day_number as dayNumber, phase FROM halls WHERE code = ? AND status = ? LIMIT 1"
  ).bind(code, "active").first();
  if (!hall) {
    return jsonResponse({ error: "\u5927\u5385\u4E0D\u5B58\u5728" }, { status: 404 }, cors);
  }
  return jsonResponse({ hall }, {}, cors);
}
__name(handleGetHall, "handleGetHall");
async function handleGetMessages(request, env, code, cors) {
  const hall = await env.DB.prepare("SELECT id FROM halls WHERE code = ? AND status = ? LIMIT 1").bind(code, "active").first();
  if (!hall) {
    return jsonResponse({ error: "\u5927\u5385\u4E0D\u5B58\u5728" }, { status: 404 }, cors);
  }
  const token = getToken(request);
  const session = await requireSession(env, hall.id, token);
  if (!session) {
    return jsonResponse({ error: "\u672A\u6388\u6743" }, { status: 401 }, cors);
  }
  const limit = Math.min(Number(new URL(request.url).searchParams.get("limit") ?? MAX_MESSAGES), 100);
  const result = await env.DB.prepare(
    "SELECT id, hall_id as hallId, player_name as sender, content, created_at as createdAt FROM messages WHERE hall_id = ? ORDER BY created_at DESC LIMIT ?"
  ).bind(hall.id, limit).all();
  const messages = result.results.slice().reverse();
  return jsonResponse({ messages }, {}, cors);
}
__name(handleGetMessages, "handleGetMessages");
async function handleGetRoster(request, env, code, cors) {
  const hall = await env.DB.prepare("SELECT id FROM halls WHERE code = ? AND status = ? LIMIT 1").bind(code, "active").first();
  if (!hall) {
    return jsonResponse({ error: "\u5927\u5385\u4E0D\u5B58\u5728" }, { status: 404 }, cors);
  }
  const token = getToken(request);
  const session = await requireSession(env, hall.id, token);
  if (!session) {
    return jsonResponse({ error: "\u672A\u6388\u6743" }, { status: 401 }, cors);
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
    ORDER BY p.created_at`
  ).bind(hall.id).all();
  return jsonResponse({ players: result.results }, {}, cors);
}
__name(handleGetRoster, "handleGetRoster");
async function handleResetDay(request, env, code, cors) {
  const body = await readJson(request);
  const storytellerKey = body.storytellerKey?.trim();
  if (!storytellerKey) {
    return jsonResponse({ error: "\u7F3A\u5C11 storytellerKey" }, { status: 400 }, cors);
  }
  const hall = await env.DB.prepare("SELECT id, storyteller_key FROM halls WHERE code = ? LIMIT 1").bind(code).first();
  if (!hall || hall.storyteller_key !== storytellerKey) {
    return jsonResponse({ error: "\u65E0\u6743\u9650\u64CD\u4F5C" }, { status: 403 }, cors);
  }
  const now = Date.now();
  await env.DB.prepare("UPDATE halls SET day_number = 1, phase = ?, updated_at = ? WHERE id = ?").bind("DAY", now, hall.id).run();
  await env.DB.prepare("DELETE FROM messages WHERE hall_id = ?").bind(hall.id).run();
  await env.DB.prepare("DELETE FROM private_requests WHERE hall_id = ?").bind(hall.id).run();
  await env.DB.prepare("DELETE FROM private_messages WHERE session_id IN (SELECT id FROM private_sessions WHERE hall_id = ?)").bind(hall.id).run();
  await env.DB.prepare("DELETE FROM private_session_members WHERE session_id IN (SELECT id FROM private_sessions WHERE hall_id = ?)").bind(hall.id).run();
  await env.DB.prepare("DELETE FROM private_sessions WHERE hall_id = ?").bind(hall.id).run();
  const updated = await env.DB.prepare(
    "SELECT id, code, name, day_number as dayNumber, phase FROM halls WHERE id = ? LIMIT 1"
  ).bind(hall.id).first();
  await broadcastToHall(env, hall.id, {
    type: "hall:update",
    hall: updated
  });
  await broadcastToHall(env, hall.id, {
    type: "system",
    message: "\u8BF4\u4E66\u4EBA\u5DF2\u91CD\u7F6E\u4E3A\u7B2C 1 \u5929\uFF0C\u804A\u5929\u4E0E\u79C1\u804A\u8BB0\u5F55\u5DF2\u6E05\u7A7A\u3002"
  });
  return jsonResponse({ hall: updated }, {}, cors);
}
__name(handleResetDay, "handleResetDay");
async function handleAdvancePhase(request, env, code, cors) {
  const body = await readJson(request);
  const storytellerKey = body.storytellerKey?.trim();
  if (!storytellerKey || !body.action) {
    return jsonResponse({ error: "\u7F3A\u5C11 storytellerKey \u6216 action" }, { status: 400 }, cors);
  }
  const hall = await env.DB.prepare(
    "SELECT id, day_number as dayNumber, phase, storyteller_key FROM halls WHERE code = ? LIMIT 1"
  ).bind(code).first();
  if (!hall || hall.storyteller_key !== storytellerKey) {
    return jsonResponse({ error: "\u65E0\u6743\u9650\u64CD\u4F5C" }, { status: 403 }, cors);
  }
  const now = Date.now();
  let nextPhase = hall.phase;
  let nextDay = hall.dayNumber;
  if (body.action === "END_DAY") {
    nextPhase = "NIGHT";
  } else if (body.action === "START_DAY") {
    nextPhase = "DAY";
    nextDay = hall.dayNumber + 1;
  }
  await env.DB.prepare("UPDATE halls SET phase = ?, day_number = ?, updated_at = ? WHERE id = ?").bind(nextPhase, nextDay, now, hall.id).run();
  if (body.action === "END_DAY") {
    const activeSessions = await env.DB.prepare(
      "SELECT id FROM private_sessions WHERE hall_id = ? AND status = ?"
    ).bind(hall.id, "ACTIVE").all();
    await env.DB.prepare(
      "UPDATE private_sessions SET status = ?, ended_at = ?, ended_by_name = ? WHERE hall_id = ? AND status = ?"
    ).bind("ENDED", now, "SYSTEM", hall.id, "ACTIVE").run();
    await env.DB.prepare(
      "UPDATE private_requests SET status = 'REJECTED', responded_at = ? WHERE hall_id = ? AND status = 'PENDING'"
    ).bind(now, hall.id).run();
    for (const session of activeSessions.results) {
      const members = await env.DB.prepare(
        "SELECT player_id as playerId FROM private_session_members WHERE session_id = ?"
      ).bind(session.id).all();
      await broadcastToHall(env, hall.id, {
        type: "private:session-end",
        sessionId: session.id,
        endedByName: "SYSTEM",
        recipients: members.results.map((member) => member.playerId)
      });
    }
  }
  const updated = await env.DB.prepare(
    "SELECT id, code, name, day_number as dayNumber, phase FROM halls WHERE id = ? LIMIT 1"
  ).bind(hall.id).first();
  await broadcastToHall(env, hall.id, {
    type: "hall:update",
    hall: updated
  });
  if (body.action === "END_DAY") {
    await broadcastToHall(env, hall.id, {
      type: "system",
      message: "\u5DF2\u8FDB\u5165\u9ED1\u591C\uFF0C\u516C\u5F00\u804A\u5929\u4E0E\u79C1\u804A\u5DF2\u6682\u505C\u3002"
    });
  }
  return jsonResponse({ hall: updated }, {}, cors);
}
__name(handleAdvancePhase, "handleAdvancePhase");
async function handleCreatePrivateRequest(request, env, code, cors) {
  const body = await readJson(request);
  const targetName = body.targetName?.trim();
  if (!targetName) {
    return jsonResponse({ error: "\u7F3A\u5C11\u76EE\u6807\u6635\u79F0" }, { status: 400 }, cors);
  }
  const hall = await env.DB.prepare("SELECT id, day_number as dayNumber, phase FROM halls WHERE code = ? LIMIT 1").bind(code).first();
  if (!hall) {
    return jsonResponse({ error: "\u5927\u5385\u4E0D\u5B58\u5728" }, { status: 404 }, cors);
  }
  if (hall.phase === "NIGHT") {
    return jsonResponse({ error: "\u9ED1\u591C\u4E2D\u65E0\u6CD5\u53D1\u8D77\u79C1\u804A" }, { status: 403 }, cors);
  }
  const token = getToken(request);
  const session = await requireSession(env, hall.id, token);
  if (!session) {
    return jsonResponse({ error: "\u672A\u6388\u6743" }, { status: 401 }, cors);
  }
  if (targetName === session.name) {
    return jsonResponse({ error: "\u4E0D\u80FD\u9080\u8BF7\u81EA\u5DF1" }, { status: 400 }, cors);
  }
  const initiatorBusy = await env.DB.prepare(
    "SELECT 1 FROM private_session_members m JOIN private_sessions s ON s.id = m.session_id WHERE s.hall_id = ? AND s.status = 'ACTIVE' AND m.player_id = ? LIMIT 1"
  ).bind(hall.id, session.playerId).first();
  if (initiatorBusy) {
    return jsonResponse({ error: "\u4F60\u6B63\u5728\u79C1\u804A\u4E2D" }, { status: 409 }, cors);
  }
  const target = await env.DB.prepare(
    "SELECT id, name, is_online as isOnline FROM players WHERE hall_id = ? AND name = ? LIMIT 1"
  ).bind(hall.id, targetName).first();
  if (!target) {
    return jsonResponse({ error: "\u672A\u627E\u5230\u8BE5\u73A9\u5BB6" }, { status: 404 }, cors);
  }
  if (!target.isOnline) {
    return jsonResponse({ error: "\u5BF9\u65B9\u4E0D\u5728\u7EBF" }, { status: 409 }, cors);
  }
  const targetBusy = await env.DB.prepare(
    "SELECT 1 FROM private_session_members m JOIN private_sessions s ON s.id = m.session_id WHERE s.hall_id = ? AND s.status = 'ACTIVE' AND m.player_id = ? LIMIT 1"
  ).bind(hall.id, target.id).first();
  if (targetBusy) {
    return jsonResponse({ error: "\u5BF9\u65B9\u6B63\u5728\u79C1\u804A\u4E2D" }, { status: 409 }, cors);
  }
  const now = Date.now();
  const requestId = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO private_requests (id, hall_id, initiator_id, initiator_name, target_id, target_name, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(requestId, hall.id, session.playerId, session.name, target.id, target.name, "PENDING", now).run();
  const requestPayload = {
    id: requestId,
    initiatorId: session.playerId,
    initiatorName: session.name,
    targetId: target.id,
    targetName: target.name,
    status: "PENDING",
    createdAt: now
  };
  await broadcastToHall(env, hall.id, {
    type: "private:request",
    request: requestPayload,
    recipients: [session.playerId, target.id]
  });
  return jsonResponse({ request: requestPayload }, {}, cors);
}
__name(handleCreatePrivateRequest, "handleCreatePrivateRequest");
async function handleRespondPrivateRequest(request, env, code, requestId, cors) {
  const body = await readJson(request);
  const response = body.response;
  if (!response) {
    return jsonResponse({ error: "\u7F3A\u5C11 response" }, { status: 400 }, cors);
  }
  const hall = await env.DB.prepare("SELECT id, day_number as dayNumber, phase FROM halls WHERE code = ? LIMIT 1").bind(code).first();
  if (!hall) {
    return jsonResponse({ error: "\u5927\u5385\u4E0D\u5B58\u5728" }, { status: 404 }, cors);
  }
  const token = getToken(request);
  const session = await requireSession(env, hall.id, token);
  if (!session) {
    return jsonResponse({ error: "\u672A\u6388\u6743" }, { status: 401 }, cors);
  }
  const requestRow = await env.DB.prepare(
    "SELECT id, initiator_id, initiator_name, target_id, target_name, status, created_at FROM private_requests WHERE id = ? AND hall_id = ? LIMIT 1"
  ).bind(requestId, hall.id).first();
  if (!requestRow) {
    return jsonResponse({ error: "\u79C1\u804A\u8BF7\u6C42\u4E0D\u5B58\u5728" }, { status: 404 }, cors);
  }
  if (requestRow.target_id !== session.playerId) {
    return jsonResponse({ error: "\u65E0\u6743\u5904\u7406\u8BE5\u8BF7\u6C42" }, { status: 403 }, cors);
  }
  if (requestRow.status !== "PENDING") {
    return jsonResponse({ error: "\u8BE5\u8BF7\u6C42\u5DF2\u5904\u7406" }, { status: 409 }, cors);
  }
  const now = Date.now();
  const nextStatus = response === "ACCEPT" ? "ACCEPTED" : "REJECTED";
  await env.DB.prepare("UPDATE private_requests SET status = ?, responded_at = ? WHERE id = ?").bind(nextStatus, now, requestId).run();
  const requestPayload = {
    id: requestRow.id,
    initiatorId: requestRow.initiator_id,
    initiatorName: requestRow.initiator_name,
    targetId: requestRow.target_id,
    targetName: requestRow.target_name,
    status: nextStatus,
    createdAt: requestRow.created_at
  };
  let sessionPayload = null;
  if (nextStatus === "ACCEPTED") {
    const sessionId = crypto.randomUUID();
    await env.DB.prepare(
      "INSERT INTO private_sessions (id, hall_id, day_number, status, created_at) VALUES (?, ?, ?, ?, ?)"
    ).bind(sessionId, hall.id, hall.dayNumber, "ACTIVE", now).run();
    await env.DB.prepare(
      "INSERT INTO private_session_members (session_id, player_id, player_name) VALUES (?, ?, ?), (?, ?, ?)"
    ).bind(
      sessionId,
      requestRow.initiator_id,
      requestRow.initiator_name,
      sessionId,
      requestRow.target_id,
      requestRow.target_name
    ).run();
    sessionPayload = {
      id: sessionId,
      participants: [requestRow.initiator_name, requestRow.target_name],
      status: "ACTIVE",
      dayNumber: hall.dayNumber,
      createdAt: now
    };
  }
  await broadcastToHall(env, hall.id, {
    type: "private:request-update",
    request: requestPayload,
    recipients: [requestRow.initiator_id, requestRow.target_id]
  });
  if (sessionPayload) {
    await broadcastToHall(env, hall.id, {
      type: "private:session-start",
      session: sessionPayload,
      recipients: [requestRow.initiator_id, requestRow.target_id]
    });
  }
  return jsonResponse({ request: requestPayload, session: sessionPayload }, {}, cors);
}
__name(handleRespondPrivateRequest, "handleRespondPrivateRequest");
async function handleWebSocket(request, env, code) {
  const hall = await env.DB.prepare("SELECT id FROM halls WHERE code = ? AND status = ? LIMIT 1").bind(code, "active").first();
  if (!hall) {
    return new Response("\u5927\u5385\u4E0D\u5B58\u5728", { status: 404 });
  }
  const token = new URL(request.url).searchParams.get("token");
  if (!token) {
    return new Response("\u7F3A\u5C11 token", { status: 401 });
  }
  const stub = env.HALL_ROOM.get(env.HALL_ROOM.idFromName(hall.id));
  const headers = new Headers(request.headers);
  headers.set("X-Hall-Id", hall.id);
  headers.set("X-Session-Token", token);
  return stub.fetch("https://hall-room/connect", {
    method: "GET",
    headers
  });
}
__name(handleWebSocket, "handleWebSocket");
async function generateUniqueHallCode(env) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const code = randomHallCode();
    const existing = await env.DB.prepare("SELECT id FROM halls WHERE code = ? LIMIT 1").bind(code).first();
    if (!existing) return code;
  }
  throw new Error("\u65E0\u6CD5\u751F\u6210\u552F\u4E00\u5927\u5385\u7801");
}
__name(generateUniqueHallCode, "generateUniqueHallCode");
function getToken(request) {
  const auth = request.headers.get("Authorization");
  if (auth && auth.startsWith("Bearer ")) {
    return auth.slice(7);
  }
  return new URL(request.url).searchParams.get("token");
}
__name(getToken, "getToken");
async function requireSession(env, hallId, token) {
  if (!token) return null;
  const payload = await verifySessionToken(token, getTokenSecret(env));
  if (!payload || payload.hallId !== hallId) return null;
  const player = await env.DB.prepare("SELECT session_version FROM players WHERE id = ? AND hall_id = ?").bind(payload.playerId, hallId).first();
  if (!player || player.session_version !== payload.ver) return null;
  return payload;
}
__name(requireSession, "requireSession");
function buildCorsOptions(request, env) {
  return {
    origin: request.headers.get("Origin"),
    allowedOrigins: parseCorsOrigins(env.CORS_ORIGINS)
  };
}
__name(buildCorsOptions, "buildCorsOptions");
async function broadcastToHall(env, hallId, payload) {
  const stub = env.HALL_ROOM.get(env.HALL_ROOM.idFromName(hallId));
  await stub.fetch("https://hall-room/broadcast", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}
__name(broadcastToHall, "broadcastToHall");
function getTokenSecret(env) {
  return resolveTokenSecret(env.TOKEN_SECRET);
}
__name(getTokenSecret, "getTokenSecret");

// node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-kC6kAk/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = worker_default;

// node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-kC6kAk/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  HallRoom,
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=worker.js.map
