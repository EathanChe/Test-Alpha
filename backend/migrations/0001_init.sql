CREATE TABLE IF NOT EXISTS halls (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  phase TEXT NOT NULL,
  day_number INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  storyteller_key TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS players (
  id TEXT PRIMARY KEY,
  hall_id TEXT NOT NULL,
  name TEXT NOT NULL,
  session_version INTEGER NOT NULL DEFAULT 1,
  is_online INTEGER NOT NULL DEFAULT 0,
  last_seen_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (hall_id, name),
  FOREIGN KEY (hall_id) REFERENCES halls(id)
);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  hall_id TEXT NOT NULL,
  player_id TEXT NOT NULL,
  player_name TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (hall_id) REFERENCES halls(id)
);

CREATE INDEX IF NOT EXISTS idx_messages_hall_created ON messages (hall_id, created_at);
CREATE INDEX IF NOT EXISTS idx_players_hall_online ON players (hall_id, is_online);
