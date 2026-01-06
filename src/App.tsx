import { FormEvent, useEffect, useMemo, useState } from 'react';
import './App.css';

type Role = 'storyteller' | 'player';

type Hall = {
  id: string;
  name: string;
  password: string;
  code: string;
  createdAt: number;
};

type ChatMessage = {
  id: string;
  hallId: string;
  sender: string;
  content: string;
  createdAt: number;
};

const HALLS_STORAGE_KEY = 'botc-halls';
const CHATS_STORAGE_KEY = 'botc-hall-chats';

function loadHalls(): Hall[] {
  const cached = localStorage.getItem(HALLS_STORAGE_KEY);
  if (!cached) return [];
  try {
    return JSON.parse(cached) as Hall[];
  } catch (error) {
    console.error('Failed to parse halls from storage', error);
    return [];
  }
}

function saveHalls(halls: Hall[]) {
  localStorage.setItem(HALLS_STORAGE_KEY, JSON.stringify(halls));
}

function loadChats(): ChatMessage[] {
  const cached = localStorage.getItem(CHATS_STORAGE_KEY);
  if (!cached) return [];
  try {
    return JSON.parse(cached) as ChatMessage[];
  } catch (error) {
    console.error('Failed to parse chats from storage', error);
    return [];
  }
}

function saveChats(chats: ChatMessage[]) {
  localStorage.setItem(CHATS_STORAGE_KEY, JSON.stringify(chats));
}

function randomId(prefix: string) {
  return `${prefix}-${crypto.randomUUID()}`;
}

function randomCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i += 1) {
    code += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return code;
}

function formatTime(timestamp: number) {
  const date = new Date(timestamp);
  return date.toLocaleString();
}

function App() {
  const [currentView, setCurrentView] = useState<'home' | 'create' | 'browse' | 'hall'>('home');
  const [halls, setHalls] = useState<Hall[]>([]);
  const [chats, setChats] = useState<ChatMessage[]>([]);
  const [activeHall, setActiveHall] = useState<Hall | null>(null);
  const [activeRole, setActiveRole] = useState<Role | null>(null);
  const [nickname, setNickname] = useState('');

  useEffect(() => {
    setHalls(loadHalls());
    setChats(loadChats());
  }, []);

  useEffect(() => {
    saveHalls(halls);
  }, [halls]);

  useEffect(() => {
    saveChats(chats);
  }, [chats]);

  const activeChat = useMemo(
    () => chats.filter((chat) => chat.hallId === activeHall?.id).sort((a, b) => a.createdAt - b.createdAt),
    [chats, activeHall?.id],
  );

  const [createName, setCreateName] = useState('');
  const [createPassword, setCreatePassword] = useState('');
  const [createResult, setCreateResult] = useState<string | null>(null);

  const [selectedHallId, setSelectedHallId] = useState('');
  const [joinPassword, setJoinPassword] = useState('');
  const [joinNickname, setJoinNickname] = useState('');
  const [joinError, setJoinError] = useState<string | null>(null);

  function handleCreateHall(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmedName = createName.trim();
    const trimmedPassword = createPassword.trim();
    if (!trimmedName || !trimmedPassword) {
      setCreateResult('请填写大厅名和密码');
      return;
    }

    const hall: Hall = {
      id: randomId('hall'),
      name: trimmedName,
      password: trimmedPassword,
      code: randomCode(),
      createdAt: Date.now(),
    };

    setHalls((prev) => [...prev, hall]);
    setCreateResult(`创建成功！大厅码：${hall.code}`);
    setCreateName('');
    setCreatePassword('');
    setActiveHall(hall);
    setActiveRole('storyteller');
    setNickname('故事讲述者');
    setCurrentView('hall');
  }

  function handleJoinHall(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedHallId) {
      setJoinError('请选择一个大厅');
      return;
    }
    const hall = halls.find((item) => item.id === selectedHallId);
    if (!hall) {
      setJoinError('未找到大厅');
      return;
    }
    if (hall.password !== joinPassword.trim()) {
      setJoinError('密码不正确');
      return;
    }
    const name = joinNickname.trim();
    if (!name) {
      setJoinError('请输入昵称');
      return;
    }

    setActiveHall(hall);
    setActiveRole('player');
    setNickname(name);
    setCurrentView('hall');
    setJoinError(null);
  }

  function handleSendMessage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const content = (formData.get('message') as string).trim();
    if (!content || !activeHall || !nickname) return;

    const message: ChatMessage = {
      id: randomId('msg'),
      hallId: activeHall.id,
      sender: nickname,
      content,
      createdAt: Date.now(),
    };

    setChats((prev) => [...prev, message]);
    form.reset();
  }

  function handleLeaveHall() {
    setActiveHall(null);
    setActiveRole(null);
    setNickname('');
    setCurrentView('home');
  }

  function HallList() {
    if (halls.length === 0) {
      return <p className="muted">暂无大厅，请说书人创建一个。</p>;
    }

    return (
      <div className="hall-grid">
        {halls.map((hall) => (
          <div key={hall.id} className="card">
            <div className="card-header">
              <div>
                <p className="pill">大厅码 {hall.code}</p>
                <h3>{hall.name}</h3>
              </div>
              <div className="timestamp">{formatTime(hall.createdAt)}</div>
            </div>
            <p className="muted">加入前需要输入密码</p>
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
          <h1>快速体验白天私聊大厅</h1>
          <p className="muted">本原型使用本地存储模拟大厅、密码与聊天记录，便于离线演示。</p>
        </div>
      </header>

      {currentView === 'home' && (
        <div className="panel">
          <div className="button-row">
            <button className="primary" onClick={() => setCurrentView('create')}>
              我是说书人：创建大厅
            </button>
            <button className="secondary" onClick={() => setCurrentView('browse')}>
              我是玩家：浏览大厅
            </button>
          </div>
          <HallList />
        </div>
      )}

      {currentView === 'create' && (
        <div className="panel">
          <div className="panel-header">
            <h2>创建大厅</h2>
            <button className="ghost" onClick={() => setCurrentView('home')}>
              返回首页
            </button>
          </div>
          <form className="form" onSubmit={handleCreateHall}>
            <label>
              大厅名称
              <input value={createName} onChange={(e) => setCreateName(e.target.value)} placeholder="例如：第 N 局" required />
            </label>
            <label>
              大厅密码
              <input
                value={createPassword}
                type="password"
                onChange={(e) => setCreatePassword(e.target.value)}
                placeholder="加入时需要输入"
                required
              />
            </label>
            <button type="submit" className="primary">
              创建并生成大厅码
            </button>
          </form>
          {createResult && <p className="success">{createResult}</p>}
        </div>
      )}

      {currentView === 'browse' && (
        <div className="panel">
          <div className="panel-header">
            <h2>加入大厅</h2>
            <button className="ghost" onClick={() => setCurrentView('home')}>
              返回首页
            </button>
          </div>
          <HallList />
          <form className="form" onSubmit={handleJoinHall}>
            <label>
              选择大厅
              <select value={selectedHallId} onChange={(e) => setSelectedHallId(e.target.value)} required>
                <option value="">请选择</option>
                {halls.map((hall) => (
                  <option key={hall.id} value={hall.id}>
                    {hall.name}（{hall.code}）
                  </option>
                ))}
              </select>
            </label>
            <label>
              大厅密码
              <input type="password" value={joinPassword} onChange={(e) => setJoinPassword(e.target.value)} required />
            </label>
            <label>
              我的昵称
              <input value={joinNickname} onChange={(e) => setJoinNickname(e.target.value)} placeholder="例如：猎人" required />
            </label>
            <button type="submit" className="primary">
              加入大厅并进入聊天
            </button>
            {joinError && <p className="error">{joinError}</p>}
          </form>
        </div>
      )}

      {currentView === 'hall' && activeHall && activeRole && (
        <div className="panel">
          <div className="panel-header">
            <div>
              <p className="pill">{activeRole === 'storyteller' ? '说书人' : '玩家'}</p>
              <h2>
                {activeHall.name} <span className="muted">（大厅码 {activeHall.code}）</span>
              </h2>
            </div>
            <button className="ghost" onClick={handleLeaveHall}>
              离开大厅
            </button>
          </div>

          <section className="card">
            <div className="card-header">
              <div>
                <h3>聊天区</h3>
                <p className="muted">消息保存在本地浏览器，用于快速原型演示。</p>
              </div>
              <span className="pill quiet">{nickname}</span>
            </div>

            <div className="chat-box">
              {activeChat.length === 0 ? (
                <p className="muted">还没有消息，发送第一条吧。</p>
              ) : (
                activeChat.map((message) => (
                  <div key={message.id} className="chat-item">
                    <div className="chat-meta">
                      <strong>{message.sender}</strong>
                      <span className="muted">{formatTime(message.createdAt)}</span>
                    </div>
                    <div>{message.content}</div>
                  </div>
                ))
              )}
            </div>

            <form className="chat-form" onSubmit={handleSendMessage}>
              <input name="message" placeholder="说点什么..." autoComplete="off" required />
              <button type="submit" className="primary">
                发送
              </button>
            </form>
          </section>
        </div>
      )}
    </div>
  );
}

export default App;
