CREATE TABLE IF NOT EXISTS private_requests (
  id TEXT PRIMARY KEY,
  hall_id TEXT NOT NULL,
  initiator_id TEXT NOT NULL,
  initiator_name TEXT NOT NULL,
  target_id TEXT NOT NULL,
  target_name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  responded_at INTEGER,
  FOREIGN KEY (hall_id) REFERENCES halls(id)
);

CREATE TABLE IF NOT EXISTS private_sessions (
  id TEXT PRIMARY KEY,
  hall_id TEXT NOT NULL,
  day_number INTEGER NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  ended_at INTEGER,
  ended_by_id TEXT,
  ended_by_name TEXT,
  FOREIGN KEY (hall_id) REFERENCES halls(id)
);

CREATE TABLE IF NOT EXISTS private_session_members (
  session_id TEXT NOT NULL,
  player_id TEXT NOT NULL,
  player_name TEXT NOT NULL,
  PRIMARY KEY (session_id, player_id),
  FOREIGN KEY (session_id) REFERENCES private_sessions(id)
);

CREATE TABLE IF NOT EXISTS private_messages (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  sender_name TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (session_id) REFERENCES private_sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_private_requests_hall_target ON private_requests (hall_id, target_id);
CREATE INDEX IF NOT EXISTS idx_private_sessions_hall_status ON private_sessions (hall_id, status);
CREATE INDEX IF NOT EXISTS idx_private_messages_session_created ON private_messages (session_id, created_at);
