CREATE TABLE kyn_state (
    singleton_id SMALLINT PRIMARY KEY CHECK (singleton_id = 1),
    version INTEGER NOT NULL CHECK (version > 0),
    snapshot JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE kyn_commands (
    command_id VARCHAR(240) PRIMARY KEY,
    operation VARCHAR(120) NOT NULL,
    actor_reference VARCHAR(200) NOT NULL,
    request_digest VARCHAR(71) NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    receipt_id VARCHAR(160) NOT NULL UNIQUE,
    result_records JSONB NOT NULL,
    response_payload JSONB,
    occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX kyn_commands_operation_occurred_idx
    ON kyn_commands (operation, occurred_at);
