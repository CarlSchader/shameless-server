CREATE EXTENSION timescaledb;

CREATE TABLE logs (
  owner_id TEXT NOT NULL,
  time bigint NOT NULL, -- timestamp microseconds from unix epoch (can be negative)
  payload BYTEA NOT NULL
);

SELECT create_hypertable('logs', 'time');

CREATE INDEX ix_owner_id_time ON logs (owner_id, time DESC);

