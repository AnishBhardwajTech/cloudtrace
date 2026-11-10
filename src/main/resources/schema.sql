-- CloudTrace MySQL schema (also runs on H2 in MySQL mode for tests)
CREATE TABLE IF NOT EXISTS cases (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    title         VARCHAR(200) NOT NULL,
    description   TEXT,
    investigator  VARCHAR(100) NOT NULL,
    status        VARCHAR(20)  NOT NULL,
    created_at    TIMESTAMP(3) NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    case_id       BIGINT       NOT NULL,
    source        VARCHAR(30)  NOT NULL,
    event_id      VARCHAR(100) NOT NULL,
    event_time    TIMESTAMP(3) NOT NULL,
    event_name    VARCHAR(100) NOT NULL,
    event_source  VARCHAR(100),
    actor         VARCHAR(255) NOT NULL,
    source_ip     VARCHAR(100),
    region        VARCHAR(30),
    error_code    VARCHAR(100),
    raw_json      LONGTEXT     NOT NULL,
    sha256        CHAR(64)     NOT NULL,
    collected_at  TIMESTAMP(3) NOT NULL,
    CONSTRAINT fk_evidence_case FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    CONSTRAINT uq_evidence_event UNIQUE (case_id, event_id)
);
CREATE INDEX idx_evidence_case_time ON evidence(case_id, event_time);
CREATE INDEX idx_evidence_actor ON evidence(case_id, actor);

CREATE TABLE IF NOT EXISTS findings (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    case_id       BIGINT       NOT NULL,
    rule_id       VARCHAR(50)  NOT NULL,
    title         VARCHAR(200) NOT NULL,
    severity      VARCHAR(10)  NOT NULL,
    actor         VARCHAR(255) NOT NULL,
    first_seen    TIMESTAMP(3) NOT NULL,
    last_seen     TIMESTAMP(3) NOT NULL,
    description   TEXT         NOT NULL,
    evidence_ids  TEXT         NOT NULL,
    CONSTRAINT fk_findings_case FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS custody_log (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    case_id       BIGINT       NOT NULL,
    action        VARCHAR(50)  NOT NULL,
    actor         VARCHAR(100) NOT NULL,
    details       TEXT,
    at            TIMESTAMP(3) NOT NULL,
    CONSTRAINT fk_custody_case FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);
