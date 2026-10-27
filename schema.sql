CREATE SEQUENCE IF NOT EXISTS seq_commit_id START 1;

CREATE TABLE IF NOT EXISTS prefix_routes (
    prefix VARCHAR,
    encoded_prefix VARCHAR,
    canonical_origin_asn BIGINT,
    observed_origin_asn BIGINT,
    as_path_normalized VARCHAR,
    path_length INTEGER,
    collector_quorum INTEGER,
    peer_visibility DOUBLE,
    rpki_status VARCHAR,
    route_classification VARCHAR,
    proof_hash VARCHAR,
    last_verified_utc VARCHAR,
    PRIMARY KEY (prefix)
);

CREATE TABLE IF NOT EXISTS route_incidents (
    incident_id VARCHAR PRIMARY KEY,
    prefix VARCHAR,
    incident_type VARCHAR,
    previous_origin BIGINT,
    current_origin BIGINT,
    previous_path VARCHAR,
    current_path VARCHAR,
    peer_visibility DOUBLE,
    rpki_status VARCHAR,
    detected_at_utc VARCHAR
);

CREATE TABLE IF NOT EXISTS route_ledger (
    commit_id BIGINT PRIMARY KEY,
    timestamp_utc VARCHAR,
    operation VARCHAR,
    prefix VARCHAR,
    origin_asn BIGINT,
    classification VARCHAR,
    proof_hash VARCHAR
);
