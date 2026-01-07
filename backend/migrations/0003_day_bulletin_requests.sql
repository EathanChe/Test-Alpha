ALTER TABLE players ADD COLUMN role TEXT NOT NULL DEFAULT 'PLAYER';

ALTER TABLE messages ADD COLUMN day_number INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS private_request_groups (
  id TEXT PRIMARY KEY,
  hall_id TEXT NOT NULL,
  day_number INTEGER NOT NULL,
  initiator_id TEXT NOT NULL,
  initiator_name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  decided_at INTEGER,
  FOREIGN KEY (hall_id) REFERENCES halls(id)
);

CREATE TABLE IF NOT EXISTS private_request_targets (
  request_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  target_name TEXT NOT NULL,
  status TEXT NOT NULL,
  responded_at INTEGER,
  PRIMARY KEY (request_id, target_id),
  FOREIGN KEY (request_id) REFERENCES private_request_groups(id)
);

CREATE TABLE IF NOT EXISTS bulletin_events (
  id TEXT PRIMARY KEY,
  hall_id TEXT NOT NULL,
  day_number INTEGER NOT NULL,
  type TEXT NOT NULL,
  participants TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (hall_id) REFERENCES halls(id)
);

CREATE INDEX IF NOT EXISTS idx_messages_hall_day_created ON messages (hall_id, day_number, created_at);
CREATE INDEX IF NOT EXISTS idx_private_request_groups_hall_status ON private_request_groups (hall_id, status);
CREATE INDEX IF NOT EXISTS idx_private_request_targets_request ON private_request_targets (request_id, status);
CREATE INDEX IF NOT EXISTS idx_bulletin_events_hall_day ON bulletin_events (hall_id, day_number, created_at);
