import { jsonResponse, resolveTokenSecret, verifySessionToken } from './utils';

export interface Env {
  DB: D1Database;
  TOKEN_SECRET: string;
}

type ConnectionInfo = {
  hallId: string;
  playerId: string;
  playerName: string;
};

type RosterEntry = {
  name: string;
  isOnline: boolean;
  role: string;
  inPrivate: boolean;
};

type HallState = {
  id: string;
  code: string;
  name: string;
  dayNumber: number;
  phase: string;
};

type ChatMessage = {
  id: string;
  hallId: string;
  sender: string;
  content: string;
  createdAt: number;
};

type PrivateRequest = {
  id: string;
  initiatorName: string;
  status: string;
  createdAt: number;
  expiresAt: number;
  dayNumber: number;
  targets: {
    name: string;
    status: string;
    respondedAt: number | null;
  }[];
};

type PrivateRequestGroupRow = {
  id: string;
  day_number: number;
  initiator_name: string;
  status: string;
  created_at: number;
  expires_at: number;
  initiator_id: string;
};

type PrivateRequestTargetRow = {
  request_id: string;
  target_id: string;
  target_name: string;
  status: string;
  responded_at: number | null;
};

type PrivateSession = {
  id: string;
  participants: string[];
  status: 'ACTIVE' | 'ENDED';
  dayNumber: number;
  createdAt: number;
  endedAt: number | null;
  endedByName: string | null;
};

type PrivateMessage = {
  id: string;
  sessionId: string;
  sender: string;
  content: string;
  createdAt: number;
};

type BulletinEvent = {
  id: string;
  hallId: string;
  dayNumber: number;
  type: string;
  participants: string[];
  createdAt: number;
};

type ClientMessage =
  | { type: 'chat:send'; content?: string }
  | { type: 'private:send'; sessionId?: string; content?: string }
  | { type: 'private:end'; sessionId?: string }
  | { type: 'ping' };

type ServerMessage =
  | {
      type: 'init';
      messages: ChatMessage[];
      roster: RosterEntry[];
      hall: HallState | null;
      privateRequests: PrivateRequest[];
      privateSessions: PrivateSession[];
      privateMessages: Record<string, PrivateMessage[]>;
    }
  | { type: 'chat:new'; message: ChatMessage }
  | { type: 'presence:update'; roster: RosterEntry[] }
  | { type: 'hall:update'; hall: HallState }
  | { type: 'private:request'; request: PrivateRequest }
  | { type: 'private:request-update'; request: PrivateRequest }
  | { type: 'private:session-start'; session: PrivateSession }
  | { type: 'private:session-end'; sessionId: string; endedByName: string | null }
  | { type: 'private:message'; message: PrivateMessage }
  | { type: 'bulletin:new'; event: BulletinEvent }
  | { type: 'pong' }
  | { type: 'system'; message: string };

type BroadcastMessage = ServerMessage & { recipients?: string[] };

type SessionMember = { playerId: string; playerName: string };

export class HallRoom {
  private state: DurableObjectState;
  private env: Env;
  private connections = new Map<WebSocket, ConnectionInfo>();

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request) {
    if (request.method === 'POST' && new URL(request.url).pathname.endsWith('/broadcast')) {
      const payload = (await request.json()) as BroadcastMessage;
      this.broadcastToHall(payload);
      return jsonResponse({ ok: true });
    }

    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('Expected WebSocket', { status: 426 });
    }

    const hallId = request.headers.get('X-Hall-Id');
    const token = request.headers.get('X-Session-Token');
    if (!hallId || !token) {
      return new Response('Missing auth headers', { status: 400 });
    }

    const session = await verifySessionToken(token, resolveTokenSecret(this.env.TOKEN_SECRET));
    if (!session || session.hallId !== hallId) {
      return new Response('Unauthorized', { status: 401 });
    }

    const playerRow = await this.env.DB.prepare(
      'SELECT session_version, name FROM players WHERE id = ? AND hall_id = ?',
    )
      .bind(session.playerId, hallId)
      .first<{ session_version: number; name: string }>();

    if (!playerRow || playerRow.session_version !== session.ver) {
      return new Response('Unauthorized', { status: 401 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];

    this.disconnectOtherSessions(session.playerId);

    server.accept();
    this.connections.set(server, {
      hallId,
      playerId: session.playerId,
      playerName: session.name,
    });

    server.addEventListener('message', (event) => {
      this.handleMessage(server, event).catch((error) => {
        console.error('WS message error', error);
      });
    });

    server.addEventListener('close', () => {
      this.handleClose(server).catch((error) => {
        console.error('WS close error', error);
      });
    });

    server.addEventListener('error', () => {
      this.handleClose(server).catch((error) => {
        console.error('WS error', error);
      });
    });

    await this.markOnline(session.playerId);
    await this.sendInit(server, hallId, session.playerId);
    await this.broadcastPresence(hallId);

    return new Response(null, { status: 101, webSocket: client });
  }

  private disconnectOtherSessions(playerId: string) {
    const socketsToClose: WebSocket[] = [];
    this.connections.forEach((info, ws) => {
      if (info.playerId === playerId) {
        socketsToClose.push(ws);
      }
    });

    socketsToClose.forEach((ws) => {
      ws.close(4001, 'Session replaced');
      this.connections.delete(ws);
    });
  }

  private async markOnline(playerId: string) {
    const now = Date.now();
    await this.env.DB.prepare('UPDATE players SET is_online = 1, last_seen_at = ? WHERE id = ?')
      .bind(now, playerId)
      .run();
  }

  private async markOfflineIfIdle(playerId: string) {
    const stillConnected = Array.from(this.connections.values()).some((info) => info.playerId === playerId);
    if (stillConnected) return;
    const now = Date.now();
    await this.env.DB.prepare('UPDATE players SET is_online = 0, last_seen_at = ? WHERE id = ?')
      .bind(now, playerId)
      .run();
  }

  private async sendInit(ws: WebSocket, hallId: string, playerId: string) {
    const hall = await this.fetchHall(hallId);
    const messages = await this.fetchRecentMessages(hallId, hall?.dayNumber ?? 1, 50);
    const roster = await this.fetchRoster(hallId);
    const privateRequests = await this.fetchPrivateRequests(hallId, playerId);
    const privateSessions = await this.fetchPrivateSessions(hallId, playerId);
    const privateMessages = await this.fetchPrivateMessages(privateSessions);
    const payload: ServerMessage = {
      type: 'init',
      messages,
      roster,
      hall,
      privateRequests,
      privateSessions,
      privateMessages,
    };
    ws.send(JSON.stringify(payload));
  }

  private async fetchHall(hallId: string) {
    return await this.env.DB.prepare(
      'SELECT id, code, name, day_number as dayNumber, phase FROM halls WHERE id = ? LIMIT 1',
    )
      .bind(hallId)
      .first<HallState>();
  }

  private async fetchRecentMessages(hallId: string, dayNumber: number, limit: number) {
    const result = await this.env.DB.prepare(
      'SELECT id, hall_id as hallId, player_name as sender, content, created_at as createdAt FROM messages WHERE hall_id = ? AND day_number = ? ORDER BY created_at DESC LIMIT ?',
    )
      .bind(hallId, dayNumber, limit)
      .all<ChatMessage>();

    return result.results.reverse();
  }

  private async fetchRoster(hallId: string) {
    const result = await this.env.DB.prepare(
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
    .all<{ name: string; isOnline: number; role: string; inPrivate: number }>();

    return result.results.map((row) => ({
      name: row.name,
      isOnline: row.isOnline === 1,
      role: row.role,
      inPrivate: row.inPrivate === 1,
    }));
  }

  private async fetchPrivateRequests(hallId: string, playerId: string) {
    await this.expireRequestsIfNeeded(hallId);

    const result = await this.env.DB.prepare(
      `SELECT DISTINCT
        g.id as id,
        g.day_number as dayNumber,
        g.initiator_id as initiatorId,
        g.initiator_name as initiatorName,
        g.status as status,
        g.created_at as createdAt,
        g.expires_at as expiresAt
      FROM private_request_groups g
      LEFT JOIN private_request_targets t ON t.request_id = g.id
      WHERE g.hall_id = ? AND g.status IN ('PENDING','DECISION')
        AND (g.initiator_id = ? OR t.target_id = ?)
      ORDER BY g.created_at DESC`,
    )
      .bind(hallId, playerId, playerId)
      .all<{
        id: string;
        dayNumber: number;
        initiatorId: string;
        initiatorName: string;
        status: string;
        createdAt: number;
        expiresAt: number;
      }>();

    const requests: PrivateRequest[] = [];
    for (const group of result.results) {
      const targets = await this.env.DB.prepare(
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
        .bind(group.id)
        .all<PrivateRequestTargetRow>();
      requests.push({
        id: group.id,
        initiatorName: group.initiatorName,
        status: group.status,
        createdAt: group.createdAt,
        expiresAt: group.expiresAt,
        dayNumber: group.dayNumber,
        targets: targets.results.map((target) => ({
          name: target.target_name,
          status: target.status,
          respondedAt: target.responded_at ?? null,
        })),
      });
    }

    return requests;
  }

  private async fetchPrivateSessions(hallId: string, playerId: string) {
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
      ORDER BY s.created_at DESC`,
    )
      .bind(hallId, playerId)
      .all<Omit<PrivateSession, 'participants'>>();

    const sessions: PrivateSession[] = [];
    for (const row of result.results) {
      const members = await this.env.DB.prepare(
        'SELECT player_name as playerName FROM private_session_members WHERE session_id = ? ORDER BY player_name',
      )
        .bind(row.id)
        .all<{ playerName: string }>();

      sessions.push({
        ...row,
        participants: members.results.map((member) => member.playerName),
        status: row.status as 'ACTIVE' | 'ENDED',
        endedAt: row.endedAt ?? null,
        endedByName: row.endedByName ?? null,
      });
    }

    return sessions;
  }

  private async fetchPrivateMessages(sessions: PrivateSession[]) {
    const result: Record<string, PrivateMessage[]> = {};
    for (const session of sessions) {
      const messages = await this.env.DB.prepare(
        'SELECT id, session_id as sessionId, sender_name as sender, content, created_at as createdAt FROM private_messages WHERE session_id = ? ORDER BY created_at ASC',
      )
        .bind(session.id)
        .all<PrivateMessage>();
      result[session.id] = messages.results;
    }
    return result;
  }

  private async expireRequestsIfNeeded(hallId: string) {
    const now = Date.now();
    const expiredGroups = await this.env.DB.prepare(
      "SELECT id FROM private_request_groups WHERE hall_id = ? AND status = 'PENDING' AND expires_at <= ?",
    )
      .bind(hallId, now)
      .all<{ id: string }>();

    for (const group of expiredGroups.results) {
      await this.env.DB.prepare(
        "UPDATE private_request_targets SET status = 'TIMEOUT', responded_at = ? WHERE request_id = ? AND status = 'PENDING'",
      )
        .bind(now, group.id)
        .run();
      await this.env.DB.prepare(
        "UPDATE private_request_groups SET status = 'DECISION', decided_at = ? WHERE id = ? AND status = 'PENDING'",
      )
        .bind(now, group.id)
        .run();

      const groupRow = await this.env.DB.prepare(
        `SELECT id, initiator_id as initiatorId, initiator_name as initiatorName, status, created_at as createdAt, expires_at as expiresAt, day_number as dayNumber
         FROM private_request_groups WHERE id = ? LIMIT 1`,
      )
        .bind(group.id)
        .first<{
          id: string;
          initiatorId: string;
          initiatorName: string;
          status: string;
          createdAt: number;
          expiresAt: number;
          dayNumber: number;
        }>();
      if (!groupRow) continue;

      const targets = await this.env.DB.prepare(
        'SELECT target_id as targetId, target_name as targetName, status, responded_at as respondedAt FROM private_request_targets WHERE request_id = ? ORDER BY target_name',
      )
        .bind(group.id)
        .all<{ targetId: string; targetName: string; status: string; respondedAt: number | null }>();

      const recipients = new Set<string>([groupRow.initiatorId, ...targets.results.map((target) => target.targetId)]);
      this.broadcastToHall(
        {
          type: 'private:request-update',
          request: {
            id: groupRow.id,
            initiatorName: groupRow.initiatorName,
            status: groupRow.status,
            createdAt: groupRow.createdAt,
            expiresAt: groupRow.expiresAt,
            dayNumber: groupRow.dayNumber,
            targets: targets.results.map((target) => ({
              name: target.targetName,
              status: target.status,
              respondedAt: target.respondedAt ?? null,
            })),
          },
          recipients: Array.from(recipients),
        },
        hallId,
      );
    }
  }

  private async broadcastPresence(hallId: string) {
    const roster = await this.fetchRoster(hallId);
    const payload: ServerMessage = { type: 'presence:update', roster };
    this.broadcastToHall(payload, hallId);
  }

  private broadcastToHall(payload: BroadcastMessage, hallId?: string) {
    const { recipients, ...message } = payload;
    const data = JSON.stringify(message);
    this.connections.forEach((info, ws) => {
      if (hallId && info.hallId !== hallId) return;
      if (recipients && !recipients.includes(info.playerId)) return;
      try {
        ws.send(data);
      } catch (error) {
        console.error('WS send error', error);
      }
    });
  }

  private async ensureDay(ws: WebSocket, hallId: string) {
    const hall = await this.fetchHall(hallId);
    if (hall?.phase === 'NIGHT') {
      ws.send(JSON.stringify({ type: 'system', message: '黑夜中无法执行该操作。' } satisfies ServerMessage));
      return null;
    }
    return hall;
  }

  private async handleMessage(ws: WebSocket, event: MessageEvent) {
    const info = this.connections.get(ws);
    if (!info) return;

    let payload: ClientMessage | null = null;
    try {
      payload = JSON.parse(typeof event.data === 'string' ? event.data : '') as ClientMessage;
    } catch {
      payload = null;
    }

    if (!payload) return;

    if (payload.type === 'ping') {
      await this.expireRequestsIfNeeded(info.hallId);
      ws.send(JSON.stringify({ type: 'pong' } satisfies ServerMessage));
      return;
    }

    if (payload.type === 'chat:send') {
      const content = (payload.content ?? '').trim();
      if (!content) return;
      const hall = await this.ensureDay(ws, info.hallId);
      if (!hall) return;
      const message: ChatMessage = {
        id: crypto.randomUUID(),
        hallId: info.hallId,
        sender: info.playerName,
        content,
        createdAt: Date.now(),
      };

      await this.env.DB.prepare(
        'INSERT INTO messages (id, hall_id, player_id, player_name, content, day_number, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      )
        .bind(message.id, info.hallId, info.playerId, info.playerName, message.content, hall.dayNumber, message.createdAt)
        .run();

      this.broadcastToHall({ type: 'chat:new', message }, info.hallId);
      return;
    }

    if (payload.type === 'private:send') {
      const sessionId = payload.sessionId?.trim();
      const content = (payload.content ?? '').trim();
      if (!sessionId || !content) return;
      if (!(await this.ensureDay(ws, info.hallId))) return;
      const members = await this.fetchSessionMembers(sessionId);
      if (!members.some((member) => member.playerId === info.playerId)) return;

      const message: PrivateMessage = {
        id: crypto.randomUUID(),
        sessionId,
        sender: info.playerName,
        content,
        createdAt: Date.now(),
      };

      await this.env.DB.prepare(
        'INSERT INTO private_messages (id, session_id, sender_id, sender_name, content, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      )
        .bind(message.id, sessionId, info.playerId, info.playerName, message.content, message.createdAt)
        .run();

      this.broadcastToHall(
        { type: 'private:message', message, recipients: members.map((member) => member.playerId) },
        info.hallId,
      );
      return;
    }

    if (payload.type === 'private:end') {
      const sessionId = payload.sessionId?.trim();
      if (!sessionId) return;
      const members = await this.fetchSessionMembers(sessionId);
      if (!members.some((member) => member.playerId === info.playerId)) return;
      const now = Date.now();

      await this.env.DB.prepare(
        'UPDATE private_sessions SET status = ?, ended_at = ?, ended_by_name = ? WHERE id = ?',
      )
        .bind('ENDED', now, info.playerName, sessionId)
        .run();

      const sessionRow = await this.env.DB.prepare(
        'SELECT day_number as dayNumber FROM private_sessions WHERE id = ? LIMIT 1',
      )
        .bind(sessionId)
        .first<{ dayNumber: number }>();
      if (sessionRow) {
        const participantNames = members.map((member) => member.playerName);
        const eventId = crypto.randomUUID();
        await this.env.DB.prepare(
          'INSERT INTO bulletin_events (id, hall_id, day_number, type, participants, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        )
          .bind(eventId, info.hallId, sessionRow.dayNumber, 'PRIVATE_END', JSON.stringify(participantNames), now)
          .run();
        this.broadcastToHall(
          {
            type: 'bulletin:new',
            event: {
              id: eventId,
              hallId: info.hallId,
              dayNumber: sessionRow.dayNumber,
              type: 'PRIVATE_END',
              participants: participantNames,
              createdAt: now,
            },
          },
          info.hallId,
        );
      }

      this.broadcastToHall(
        {
          type: 'private:session-end',
          sessionId,
          endedByName: info.playerName,
          recipients: members.map((member) => member.playerId),
        },
        info.hallId,
      );
      await this.broadcastPresence(info.hallId);
    }
  }

  private async fetchSessionMembers(sessionId: string) {
    const result = await this.env.DB.prepare(
      'SELECT player_id as playerId, player_name as playerName FROM private_session_members WHERE session_id = ?',
    )
      .bind(sessionId)
      .all<SessionMember>();

    return result.results;
  }

  private async handleClose(ws: WebSocket) {
    const info = this.connections.get(ws);
    if (!info) return;
    this.connections.delete(ws);
    await this.markOfflineIfIdle(info.playerId);
    await this.broadcastPresence(info.hallId);
  }
}
