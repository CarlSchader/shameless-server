CREATE EXTENSION timescaledb;

CREATE TABLE logs (
  owner_id TEXT NOT NULL,
  ts TIMESTAMPTZ NOT NULL,
  payload BYTEA NOT NULL
);

SELECT create_hypertable('logs', 'ts');
