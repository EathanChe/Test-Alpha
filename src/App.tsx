import { FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import './App.css';

type Phase = 'DAY' | 'NIGHT';

type HallSummary = {
  id: string;
  code: string;
  name: string;
  dayNumber: number;
  phase: Phase;
  createdAt: number;
  onlineCount: number;
};

type HallDetail = {
  id: string;
  code: string;
  name: string;
  dayNumber: number;
  phase: Phase;
};

type ChatMessage = {
  id: string;
  hallId: string;
  sender: string;
  content: string;
  createdAt: number;
};

type RosterEntry = {
  name: string;
  isOnline: boolean;
  inPrivate: boolean;
};

type PrivateRequest = {
  id: string;
  initiatorName: string;
  targetName: string;
  status: 'PENDING' | 'ACCEPTED' | 'REJECTED';
  createdAt: number;
};

type PrivateSession = {
  id: string;
  participants: string[];
  status: 'ACTIVE' | 'ENDED';
  dayNumber: number;
  createdAt: number;
  endedAt?: number | null;
  endedByName?: string | null;
};

type PrivateMessage = {
  id: string;
  sessionId: string;
  sender: string;
  content: string;
  createdAt: number;
};

type SessionCache = {
  hall: HallDetail;
  sessionToken: string;
  playerName: string;
  storytellerKey?: string;
};

type WsPayload =
  | {
      type: 'init';
      messages: ChatMessage[];
      roster: RosterEntry[];
      hall: HallDetail | null;
      privateRequests: PrivateRequest[];
      privateSessions: PrivateSession[];
      privateMessages: Record<string, PrivateMessage[]>;
    }
  | { type: 'chat:new'; message: ChatMessage }
  | { type: 'presence:update'; roster: RosterEntry[] }
  | { type: 'hall:update'; hall: HallDetail }
  | { type: 'private:request'; request: PrivateRequest }
  | { type: 'private:request-update'; request: PrivateRequest }
  | { type: 'private:session-start'; session: PrivateSession }
  | { type: 'private:session-end'; sessionId: string; endedByName: string | null }
  | { type: 'private:message'; message: PrivateMessage }
  | { type: 'system'; message: string };

const DEFAULT_API_ROOT = 'http://127.0.0.1:8787';
const RAW_API_ROOT = (import.meta.env.VITE_API_BASE as string | undefined)?.trim();
const IS_PROD = import.meta.env.PROD;
const API_ROOT = (RAW_API_ROOT && RAW_API_ROOT.length > 0
  ? RAW_API_ROOT
  : IS_PROD
    ? ''
    : DEFAULT_API_ROOT
).replace(/\/$/, '');
const SESSION_STORAGE_KEY = 'botc-session';

function buildApiUrl(path: string) {
  return `${API_ROOT}${path}`;
}

function buildWsUrl(path: string) {
  const base = API_ROOT || window.location.origin;
  return `${base.replace(/^http/, 'ws')}${path}`;
}

async function apiRequest<T>(path: string, options: RequestInit = {}) {
  if (!API_ROOT) {
    throw new Error('VITE_API_BASE 未配置');
  }
  const response = await fetch(buildApiUrl(path), {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers ?? {}),
    },
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = data?.error ?? '请求失败';
    throw new Error(message);
  }
  return data as T;
}

function formatTime(timestamp: number) {
  const date = new Date(timestamp);
  return date.toLocaleString('zh-CN', {
    hour12: false,
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function App() {
  const [currentView, setCurrentView] = useState<'home' | 'create' | 'browse' | 'hall'>('home');
  const [halls, setHalls] = useState<HallSummary[]>([]);

  const [activeHall, setActiveHall] = useState<HallDetail | null>(null);
  const [playerName, setPlayerName] = useState('');
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [storytellerKey, setStorytellerKey] = useState<string | null>(null);

  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [roster, setRoster] = useState<RosterEntry[]>([]);
  const [privateRequests, setPrivateRequests] = useState<PrivateRequest[]>([]);
  const [privateSessions, setPrivateSessions] = useState<PrivateSession[]>([]);
  const [privateMessages, setPrivateMessages] = useState<Record<string, PrivateMessage[]>>({});
  const [activePrivateSessionId, setActivePrivateSessionId] = useState<string | null>(null);

  const [notice, setNotice] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<'offline' | 'connecting' | 'online'>('offline');
  const [apiWarning, setApiWarning] = useState<string | null>(null);

  const [createName, setCreateName] = useState('');
  const [createPassword, setCreatePassword] = useState('');
  const [createResult, setCreateResult] = useState<string | null>(null);
  const [createError, setCreateError] = useState<string | null>(null);

  const [selectedHallCode, setSelectedHallCode] = useState('');
  const [joinPassword, setJoinPassword] = useState('');
  const [joinNickname, setJoinNickname] = useState('');
  const [joinError, setJoinError] = useState<string | null>(null);

  const [chatDraft, setChatDraft] = useState('');
  const [privateDraft, setPrivateDraft] = useState('');
  const [inboundRequest, setInboundRequest] = useState<PrivateRequest | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);
  const reconnectAttemptRef = useRef(0);

  useEffect(() => {
    const cached = sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!cached) return;
    try {
      const session = JSON.parse(cached) as SessionCache;
      setActiveHall(session.hall);
      setSessionToken(session.sessionToken);
      setPlayerName(session.playerName);
      setStorytellerKey(session.storytellerKey ?? null);
      setCurrentView('hall');
    } catch {
      sessionStorage.removeItem(SESSION_STORAGE_KEY);
    }
  }, []);

  useEffect(() => {
    if (IS_PROD && !RAW_API_ROOT) {
      setApiWarning('未配置 VITE_API_BASE，生产环境无法请求后端。');
    }
    console.info('[BOTC] API base:', API_ROOT || '未配置');
  }, []);

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(null), 3000);
    return () => window.clearTimeout(timer);
  }, [notice]);

  useEffect(() => {
    if (currentView !== 'home' && currentView !== 'browse') return;
    let active = true;
    let timer: number | null = null;

    const loadHalls = async () => {
      try {
        const data = await apiRequest<{ halls: HallSummary[] }>('/api/halls');
        if (active) {
          setHalls(data.halls);
          setApiWarning(null);
        }
      } catch (error) {
        const message = (error as Error).message;
        if (message === 'VITE_API_BASE 未配置') {
          setApiWarning(message);
        }
        console.error(error);
      }
    };

    const startPolling = () => {
      if (timer !== null) return;
      loadHalls();
      timer = window.setInterval(loadHalls, 5000);
    };

    const stopPolling = () => {
      if (timer === null) return;
      window.clearInterval(timer);
      timer = null;
    };

    const handleVisibility = () => {
      if (document.hidden) {
        stopPolling();
      } else {
        loadHalls();
        startPolling();
      }
    };

    startPolling();
    document.addEventListener('visibilitychange', handleVisibility);

    return () => {
      active = false;
      stopPolling();
      document.removeEventListener('visibilitychange', handleVisibility);
    };
  }, [currentView]);

  useEffect(() => {
    if (!activeHall || !sessionToken || !API_ROOT) return;
    let shouldReconnect = true;

    const connect = () => {
      setConnectionStatus('connecting');
      const ws = new WebSocket(buildWsUrl(`/ws/halls/${activeHall.code}?token=${encodeURIComponent(sessionToken)}`));
      wsRef.current = ws;

      ws.onopen = () => {
        reconnectAttemptRef.current = 0;
        setConnectionStatus('online');
      };

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data as string) as WsPayload;
          if (payload.type === 'init') {
            setMessages(payload.messages);
            setRoster(payload.roster);
            setPrivateRequests(payload.privateRequests);
            setPrivateSessions(payload.privateSessions);
            setPrivateMessages(payload.privateMessages);
            if (payload.hall) {
              setActiveHall(payload.hall);
            }
            const pending = payload.privateRequests.find(
              (request) => request.targetName === playerName && request.status === 'PENDING',
            );
            if (pending) {
              setInboundRequest(pending);
            }
          }
          if (payload.type === 'chat:new') {
            setMessages((prev) => [...prev, payload.message]);
          }
          if (payload.type === 'presence:update') {
            setRoster(payload.roster);
          }
          if (payload.type === 'hall:update') {
            setActiveHall(payload.hall);
          }
          if (payload.type === 'private:request') {
            setPrivateRequests((prev) =>
              prev.some((item) => item.id === payload.request.id) ? prev : [...prev, payload.request],
            );
            if (payload.request.targetName === playerName && payload.request.status === 'PENDING') {
              setInboundRequest(payload.request);
            }
          }
          if (payload.type === 'private:request-update') {
            setPrivateRequests((prev) => {
              const exists = prev.some((item) => item.id === payload.request.id);
              if (!exists) return [...prev, payload.request];
              return prev.map((item) => (item.id === payload.request.id ? payload.request : item));
            });
            if (payload.request.targetName === playerName && payload.request.status !== 'PENDING') {
              setInboundRequest(null);
            }
          }
          if (payload.type === 'private:session-start') {
            setPrivateSessions((prev) =>
              prev.some((item) => item.id === payload.session.id) ? prev : [...prev, payload.session],
            );
            if (payload.session.participants.includes(playerName)) {
              setActivePrivateSessionId(payload.session.id);
            }
          }
          if (payload.type === 'private:session-end') {
            setPrivateSessions((prev) =>
              prev.map((item) =>
                item.id === payload.sessionId
                  ? { ...item, status: 'ENDED', endedByName: payload.endedByName ?? item.endedByName }
                  : item,
              ),
            );
            setActivePrivateSessionId((prev) => (prev === payload.sessionId ? null : prev));
          }
          if (payload.type === 'private:message') {
            setPrivateMessages((prev) => ({
              ...prev,
              [payload.message.sessionId]: [
                ...(prev[payload.message.sessionId] ?? []),
                payload.message,
              ],
            }));
          }
          if (payload.type === 'system') {
            setNotice(payload.message);
            if (payload.message.includes('清空')) {
              setMessages([]);
              setPrivateSessions([]);
              setPrivateMessages({});
            }
          }
        } catch (error) {
          console.error('WS message error', error);
        }
      };

      ws.onclose = () => {
        setConnectionStatus('offline');
        if (!shouldReconnect) return;
        scheduleReconnect();
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    const scheduleReconnect = () => {
      if (reconnectTimerRef.current) return;
      reconnectAttemptRef.current += 1;
      const delay = Math.min(5000, 500 + reconnectAttemptRef.current * 500);
      reconnectTimerRef.current = window.setTimeout(() => {
        reconnectTimerRef.current = null;
        connect();
      }, delay);
    };

    connect();

    return () => {
      shouldReconnect = false;
      if (reconnectTimerRef.current) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      wsRef.current?.close();
    };
  }, [activeHall, sessionToken]);

  const activeHallSummary = useMemo(
    () => halls.find((hall) => hall.code === activeHall?.code) ?? null,
    [halls, activeHall?.code],
  );

  const isStoryteller = Boolean(storytellerKey);
  const isNight = activeHall?.phase === 'NIGHT';
  const activePrivateSession = useMemo(
    () => privateSessions.find((session) => session.id === activePrivateSessionId) ?? null,
    [privateSessions, activePrivateSessionId],
  );
  const activePrivateMessages = activePrivateSessionId ? privateMessages[activePrivateSessionId] ?? [] : [];
  const onlineCount = roster.filter((player) => player.isOnline).length;

  function saveSession(session: SessionCache) {
    sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
  }

  function clearSession() {
    sessionStorage.removeItem(SESSION_STORAGE_KEY);
  }

  async function handleCreateHall(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmedName = createName.trim();
    const trimmedPassword = createPassword.trim();
    if (!trimmedName || !trimmedPassword) {
      setCreateError('请填写大厅名和密码');
      return;
    }

    try {
      const data = await apiRequest<{ hallId: string; hallCode: string; storytellerKey: string }>('/api/halls', {
        method: 'POST',
        body: JSON.stringify({ name: trimmedName, password: trimmedPassword }),
      });

      setCreateResult(`创建成功！大厅码：${data.hallCode}`);
      setCreateError(null);
      setStorytellerKey(data.storytellerKey);

      const joinData = await apiRequest<{
        sessionToken: string;
        playerId: string;
        hall: HallDetail;
      }>(`/api/halls/${data.hallCode}/join`, {
        method: 'POST',
        body: JSON.stringify({ playerName: '说书人', password: trimmedPassword }),
      });

      setActiveHall(joinData.hall);
      setPlayerName('说书人');
      setSessionToken(joinData.sessionToken);
      saveSession({
        hall: joinData.hall,
        sessionToken: joinData.sessionToken,
        playerName: '说书人',
        storytellerKey: data.storytellerKey,
      });

      setCurrentView('hall');
    } catch (error) {
      setCreateError((error as Error).message);
    }
  }

  async function handleJoinHall(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedHallCode) {
      setJoinError('请选择一个大厅');
      return;
    }
    const trimmedNickname = joinNickname.trim();
    if (!trimmedNickname) {
      setJoinError('请输入昵称');
      return;
    }

    try {
      const data = await apiRequest<{
        sessionToken: string;
        playerId: string;
        hall: HallDetail;
      }>(`/api/halls/${selectedHallCode}/join`, {
        method: 'POST',
        body: JSON.stringify({ playerName: trimmedNickname, password: joinPassword.trim() }),
      });

      setActiveHall(data.hall);
      setPlayerName(trimmedNickname);
      setSessionToken(data.sessionToken);
      setStorytellerKey(null);
      saveSession({ hall: data.hall, sessionToken: data.sessionToken, playerName: trimmedNickname });

      setCurrentView('hall');
      setJoinError(null);
    } catch (error) {
      setJoinError((error as Error).message);
    }
  }

  async function handleResetDay() {
    if (!activeHall || !storytellerKey) return;
    try {
      const data = await apiRequest<{ hall: HallDetail }>(`/api/halls/${activeHall.code}/admin/reset-day`, {
        method: 'POST',
        body: JSON.stringify({ storytellerKey }),
      });
      setActiveHall(data.hall);
      setMessages([]);
      setPrivateSessions([]);
      setPrivateMessages({});
    } catch (error) {
      setNotice((error as Error).message);
    }
  }

  async function handleAdvancePhase(action: 'END_DAY' | 'START_DAY') {
    if (!activeHall || !storytellerKey) return;
    try {
      const data = await apiRequest<{ hall: HallDetail }>(`/api/halls/${activeHall.code}/admin/phase`, {
        method: 'POST',
        body: JSON.stringify({ storytellerKey, action }),
      });
      setActiveHall(data.hall);
    } catch (error) {
      setNotice((error as Error).message);
    }
  }

  function handleLeaveHall() {
    wsRef.current?.close();
    setActiveHall(null);
    setPlayerName('');
    setSessionToken(null);
    setStorytellerKey(null);
    setMessages([]);
    setRoster([]);
    setPrivateRequests([]);
    setPrivateSessions([]);
    setPrivateMessages({});
    setActivePrivateSessionId(null);
    setInboundRequest(null);
    clearSession();
    setCurrentView('home');
  }

  function handleSendMessage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!chatDraft.trim()) return;
    if (isNight) {
      setNotice('黑夜中无法发送公开聊天');
      return;
    }
    if (connectionStatus !== 'online') {
      setNotice('当前离线，无法发送消息');
      return;
    }
    wsRef.current?.send(JSON.stringify({ type: 'chat:send', content: chatDraft.trim() }));
    setChatDraft('');
  }

  async function handleCreatePrivateRequest(targetName: string) {
    if (!activeHall || !sessionToken) return;
    if (isNight) {
      setNotice('黑夜中无法发起私聊');
      return;
    }
    try {
      await apiRequest<{ request: PrivateRequest }>(`/api/halls/${activeHall.code}/private-requests`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({ targetName }),
      });
      setNotice(`已向 ${targetName} 发起私聊申请`);
    } catch (error) {
      setNotice((error as Error).message);
    }
  }

  async function handleRespondPrivateRequest(response: 'ACCEPT' | 'REJECT') {
    if (!activeHall || !sessionToken || !inboundRequest) return;
    try {
      const data = await apiRequest<{ request: PrivateRequest; session: PrivateSession | null }>(
        `/api/halls/${activeHall.code}/private-requests/${inboundRequest.id}/respond`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${sessionToken}`,
          },
          body: JSON.stringify({ response }),
        },
      );
      setPrivateRequests((prev) =>
        prev.map((item) => (item.id === data.request.id ? data.request : item)),
      );
      setInboundRequest(null);
    } catch (error) {
      setNotice((error as Error).message);
    }
  }

  function handleSendPrivateMessage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!activePrivateSessionId) return;
    if (!privateDraft.trim()) return;
    if (isNight) {
      setNotice('黑夜中无法发送私聊');
      return;
    }
    if (connectionStatus !== 'online') {
      setNotice('当前离线，无法发送私聊');
      return;
    }
    wsRef.current?.send(
      JSON.stringify({ type: 'private:send', sessionId: activePrivateSessionId, content: privateDraft.trim() }),
    );
    setPrivateDraft('');
  }

  function handleEndPrivateSession() {
    if (!activePrivateSessionId) return;
    wsRef.current?.send(JSON.stringify({ type: 'private:end', sessionId: activePrivateSessionId }));
  }

  function HallList() {
    if (halls.length === 0) {
      return <p className="muted">暂无大厅，请说书人创建一个。</p>;
    }

    return (
      <div className="hall-grid">
        {halls.map((hall) => (
          <div key={hall.id} className="card hall-card">
            <div className="card-header">
              <div>
                <p className="badge">大厅码 {hall.code}</p>
                <h3>{hall.name}</h3>
              </div>
              <div className="timestamp">{formatTime(hall.createdAt)}</div>
            </div>
            <div className="hall-meta">
              <span>第 {hall.dayNumber} 天</span>
              <span className={hall.phase === 'DAY' ? 'tag day' : 'tag night'}>
                {hall.phase === 'DAY' ? '白天' : '黑夜'}
              </span>
              <span>{hall.onlineCount} 人在线</span>
            </div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="page">
      <header className="hero">
        <div>
          <p className="logo">血染大厅 · BOTC Day Chat Manager</p>
          <h1>血染钟楼白天私聊大厅 · 多人在线 MVP</h1>
          <p className="muted">前端通过 API + WebSocket 实现多人实时聊天。</p>
          <p className="muted small">API: {API_ROOT || '未配置'}</p>
        </div>
        {currentView === 'home' && (
          <div className="hero-actions">
            <button className="btn primary" onClick={() => setCurrentView('create')}>
              我是说书人：创建大厅
            </button>
            <button className="btn secondary" onClick={() => setCurrentView('browse')}>
              我是玩家：浏览大厅
            </button>
          </div>
        )}
      </header>

      {apiWarning && <div className="toast">{apiWarning}</div>}
      {notice && <div className="toast">{notice}</div>}

      {currentView === 'home' && (
        <div className="surface panel">
          <div className="panel-header">
            <h2>大厅列表</h2>
            <span className="muted">实时刷新 · 多端同步</span>
          </div>
          <HallList />
        </div>
      )}

      {currentView === 'create' && (
        <div className="surface panel">
          <div className="panel-header">
            <h2>创建大厅</h2>
            <button className="btn ghost" onClick={() => setCurrentView('home')}>
              返回首页
            </button>
          </div>
          <form className="form" onSubmit={handleCreateHall}>
            <label>
              大厅名称
              <input value={createName} onChange={(event) => setCreateName(event.target.value)} placeholder="例如：第 N 局" required />
            </label>
            <label>
              大厅密码
              <input
                value={createPassword}
                type="password"
                onChange={(event) => setCreatePassword(event.target.value)}
                placeholder="加入时需要输入"
                required
              />
            </label>
            <button type="submit" className="btn primary">
              创建并进入大厅
            </button>
          </form>
          {createResult && <p className="success">{createResult}</p>}
          {createError && <p className="error">{createError}</p>}
          {storytellerKey && (
            <div className="status-item">
              <strong>storytellerKey</strong>
              <span className="muted">{storytellerKey}</span>
            </div>
          )}
        </div>
      )}

      {currentView === 'browse' && (
        <div className="surface panel">
          <div className="panel-header">
            <h2>加入大厅</h2>
            <button className="btn ghost" onClick={() => setCurrentView('home')}>
              返回首页
            </button>
          </div>
          <HallList />
          <form className="form" onSubmit={handleJoinHall}>
            <label>
              选择大厅
              <select value={selectedHallCode} onChange={(event) => setSelectedHallCode(event.target.value)} required>
                <option value="">请选择</option>
                {halls.map((hall) => (
                  <option key={hall.id} value={hall.code}>
                    {hall.name}（{hall.code}）
                  </option>
                ))}
              </select>
            </label>
            <label>
              大厅密码
              <input type="password" value={joinPassword} onChange={(event) => setJoinPassword(event.target.value)} required />
            </label>
            <label>
              我的昵称
              <input value={joinNickname} onChange={(event) => setJoinNickname(event.target.value)} placeholder="例如：猎人" required />
            </label>
            <button type="submit" className="btn primary">
              加入大厅并进入聊天
            </button>
            {joinError && <p className="error">{joinError}</p>}
          </form>
        </div>
      )}

      {currentView === 'hall' && activeHall && sessionToken && (
        <div className="surface panel hall-panel">
          <div className="panel-header hall-header">
            <div>
              <div className="pill-row">
                <span className={activeHall.phase === 'DAY' ? 'tag day' : 'tag night'}>
                  {activeHall.phase === 'DAY' ? '白天' : '黑夜'}
                </span>
                <span className="badge">第 {activeHall.dayNumber} 天</span>
                <span className="badge">{isStoryteller ? '说书人' : '玩家'}</span>
                <span className={`badge ${connectionStatus}`}>连接：{connectionStatus === 'online' ? '在线' : '离线'}</span>
              </div>
              <h2>
                {activeHall.name} <span className="muted">（大厅码 {activeHall.code}）</span>
              </h2>
            </div>
            <button className="btn ghost" onClick={handleLeaveHall}>
              离开大厅
            </button>
          </div>

          {isNight && <div className="night-banner">黑夜中，操作已暂停，等待说书人开启白天。</div>}

          {isStoryteller && (
            <section className="card storyteller-panel">
              <div className="card-header">
                <div>
                  <h3>说书人控制台</h3>
                  <p className="muted">切换白天/黑夜、重开游戏。</p>
                </div>
                <span className="badge">当前：{activeHall.phase === 'DAY' ? '白天' : '黑夜'}</span>
              </div>
              <div className="button-row">
                <button className="btn secondary" onClick={() => handleAdvancePhase('END_DAY')} disabled={isNight}>
                  结束白天 → 黑夜
                </button>
                <button className="btn secondary" onClick={() => handleAdvancePhase('START_DAY')} disabled={!isNight}>
                  开启白天 → Day +1
                </button>
                <button className="btn warning" onClick={handleResetDay}>
                  结束游戏并重开
                </button>
              </div>
            </section>
          )}

          <div className="hall-grid-layout">
            <section className="card roster-card">
              <div className="card-header">
                <div>
                  <h3>在线列表</h3>
                  <p className="muted">当前在线玩家</p>
                </div>
                <span className="badge">{roster.filter((player) => player.isOnline).length} 人在线</span>
              </div>
              <div className="roster">
                {roster.length === 0 && <p className="muted">暂无在线玩家。</p>}
                {roster.map((player) => (
                  <div key={player.name} className="roster-item">
                    <div>
                      <strong>{player.name}</strong>
                      <div className="muted small">{player.isOnline ? '在线' : '离线'}</div>
                    </div>
                    <div className="roster-actions">
                      {player.inPrivate && <span className="tag">私聊中</span>}
                      {player.name === playerName ? (
                        <span className="tag">你</span>
                      ) : (
                        <button
                          className="btn ghost small"
                          onClick={() => handleCreatePrivateRequest(player.name)}
                          disabled={!player.isOnline || isNight}
                        >
                          申请私聊
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <section className="card chat-card">
              <div className="card-header">
                <div>
                  <h3>公开聊天</h3>
                  <p className="muted">消息实时同步</p>
                </div>
                <span className="badge">{activeHallSummary?.onlineCount ?? onlineCount} 在线</span>
              </div>
              <div className="message-list">
                {messages.length === 0 ? (
                  <p className="muted">还没有消息，发送第一条吧。</p>
                ) : (
                  messages.map((message) => (
                    <div key={message.id} className="message">
                      <div className="message-meta">
                        <strong>{message.sender}</strong>
                        <span className="muted">{formatTime(message.createdAt)}</span>
                      </div>
                      <div>{message.content}</div>
                    </div>
                  ))
                )}
              </div>
              <form className="message-form" onSubmit={handleSendMessage}>
                <input
                  value={chatDraft}
                  onChange={(event) => setChatDraft(event.target.value)}
                  placeholder={
                    isNight ? '黑夜中无法发送' : connectionStatus === 'online' ? '说点什么...' : '离线中，等待重连'
                  }
                  disabled={connectionStatus !== 'online' || isNight}
                />
                <button className="btn primary" type="submit" disabled={connectionStatus !== 'online' || isNight}>
                  发送
                </button>
              </form>
            </section>

            <section className="card request-card">
              <div className="card-header">
                <div>
                  <h3>私聊列表</h3>
                  <p className="muted">从在线列表发起私聊申请。</p>
                </div>
                <span className="badge">{privateSessions.filter((session) => session.status === 'ACTIVE').length} 进行中</span>
              </div>
              <div className="request-status">
                {privateRequests.filter((req) => req.initiatorName === playerName).length === 0 && (
                  <p className="muted">暂无发起的私聊申请。</p>
                )}
                {privateRequests
                  .filter((req) => req.initiatorName === playerName)
                  .slice(0, 3)
                  .map((req) => (
                    <div key={req.id} className="status-item">
                      <strong>申请 {req.targetName}</strong>
                      <span className="muted">
                        状态：
                        {req.status === 'PENDING' && '等待回应'}
                        {req.status === 'ACCEPTED' && '已接受'}
                        {req.status === 'REJECTED' && '已拒绝'}
                      </span>
                    </div>
                  ))}
              </div>
              <div className="session-list">
                {privateSessions.length === 0 && <p className="muted">暂无私聊会话。</p>}
                {privateSessions.map((session) => (
                  <div key={session.id} className="status-item">
                    <strong>{session.participants.join('、')}</strong>
                    <span className="muted">{session.status === 'ACTIVE' ? '进行中' : '已结束'}</span>
                    {session.status === 'ACTIVE' && (
                      <button className="btn ghost small" onClick={() => setActivePrivateSessionId(session.id)}>
                        打开
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </section>
          </div>
        </div>
      )}

      {inboundRequest && (
        <div className="modal-backdrop" onClick={() => undefined}>
          <div className="modal">
            <div className="modal-header">
              <h3>私聊申请</h3>
              <span className="tag">来自 {inboundRequest.initiatorName}</span>
            </div>
            <div className="modal-body">
              <p>你收到了来自 {inboundRequest.initiatorName} 的私聊申请。</p>
              <p className="muted">参与人：{[inboundRequest.initiatorName, inboundRequest.targetName].join('、')}</p>
            </div>
            <div className="modal-footer">
              <button className="btn secondary" onClick={() => handleRespondPrivateRequest('REJECT')}>
                拒绝
              </button>
              <button className="btn primary" onClick={() => handleRespondPrivateRequest('ACCEPT')} disabled={isNight}>
                同意
              </button>
            </div>
          </div>
        </div>
      )}

      {activePrivateSession && (
        <div className="drawer">
          <div className="drawer-header">
            <div>
              <strong>私聊进行中</strong>
              <p className="muted">成员：{activePrivateSession.participants.join('、')}</p>
            </div>
            <button className="btn ghost" onClick={handleEndPrivateSession}>
              结束私聊
            </button>
          </div>
          <div className="drawer-body">
            <div className="message-list">
              {activePrivateMessages.length === 0 ? (
                <p className="muted">还没有私聊消息。</p>
              ) : (
                activePrivateMessages.map((message) => (
                  <div key={message.id} className="message">
                    <div className="message-meta">
                      <strong>{message.sender}</strong>
                      <span className="muted">{formatTime(message.createdAt)}</span>
                    </div>
                    <div>{message.content}</div>
                  </div>
                ))
              )}
            </div>
            <form className="message-form" onSubmit={handleSendPrivateMessage}>
              <input
                value={privateDraft}
                onChange={(event) => setPrivateDraft(event.target.value)}
                placeholder={isNight ? '黑夜中无法发送' : '私聊消息...'}
                disabled={isNight}
              />
              <button className="btn primary" type="submit" disabled={isNight}>
                发送
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
