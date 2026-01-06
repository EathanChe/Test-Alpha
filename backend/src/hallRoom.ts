import { jsonResponse, verifySessionToken } from './utils';

export interface Env {
  DB: D1Database;
  TOKEN_SECRET: string;
}

type ConnectionInfo = {
  hallId: string;
  playerId: string;
  playerName: string;
};

type ClientMessage = {
  type: 'chat:send' | 'ping';
  content?: string;
};

type ServerMessage =
  | { type: 'init'; messages: ChatMessage[]; players: string[] }
  | { type: 'chat:new'; message: ChatMessage }
  | { type: 'presence:update'; players: string[] }
  | { type: 'pong' }
  | { type: 'system'; message: string };

type ChatMessage = {
  id: string;
  hallId: string;
  sender: string;
  content: string;
  createdAt: number;
};

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
      const payload = (await request.json()) as ServerMessage;
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

    const session = await verifySessionToken(token, this.env.TOKEN_SECRET);
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
    await this.sendInit(server, hallId);
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

  private async sendInit(ws: WebSocket, hallId: string) {
    const messages = await this.fetchRecentMessages(hallId, 50);
    const players = await this.fetchOnlinePlayers(hallId);
    const payload: ServerMessage = { type: 'init', messages, players };
    ws.send(JSON.stringify(payload));
  }

  private async fetchRecentMessages(hallId: string, limit: number) {
    const result = await this.env.DB.prepare(
      'SELECT id, hall_id as hallId, player_name as sender, content, created_at as createdAt FROM messages WHERE hall_id = ? ORDER BY created_at DESC LIMIT ?',
    )
      .bind(hallId, limit)
      .all<ChatMessage>();

    return result.results.reverse();
  }

  private async fetchOnlinePlayers(hallId: string) {
    const result = await this.env.DB.prepare(
      'SELECT name FROM players WHERE hall_id = ? AND is_online = 1 ORDER BY created_at',
    )
      .bind(hallId)
      .all<{ name: string }>();

    return result.results.map((row) => row.name);
  }

  private async broadcastPresence(hallId: string) {
    const players = await this.fetchOnlinePlayers(hallId);
    const payload: ServerMessage = { type: 'presence:update', players };
    this.broadcastToHall(payload, hallId);
  }

  private broadcastToHall(payload: ServerMessage, hallId?: string) {
    const data = JSON.stringify(payload);
    this.connections.forEach((info, ws) => {
      if (!hallId || info.hallId === hallId) {
        try {
          ws.send(data);
        } catch (error) {
          console.error('WS send error', error);
        }
      }
    });
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
      ws.send(JSON.stringify({ type: 'pong' } satisfies ServerMessage));
      return;
    }

    if (payload.type === 'chat:send') {
      const content = (payload.content ?? '').trim();
      if (!content) return;
      const message: ChatMessage = {
        id: crypto.randomUUID(),
        hallId: info.hallId,
        sender: info.playerName,
        content,
        createdAt: Date.now(),
      };

      await this.env.DB.prepare(
        'INSERT INTO messages (id, hall_id, player_id, player_name, content, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      )
        .bind(message.id, info.hallId, info.playerId, info.playerName, message.content, message.createdAt)
        .run();

      this.broadcastToHall({ type: 'chat:new', message }, info.hallId);
    }
  }

  private async handleClose(ws: WebSocket) {
    const info = this.connections.get(ws);
    if (!info) return;
    this.connections.delete(ws);
    await this.markOfflineIfIdle(info.playerId);
    await this.broadcastPresence(info.hallId);
  }
}
