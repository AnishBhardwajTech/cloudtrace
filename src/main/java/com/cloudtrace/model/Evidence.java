package com.cloudtrace.model;

import java.time.Instant;
import java.util.Objects;

/**
 * One AWS log event preserved as evidence. The original record is kept verbatim
 * in {@code rawJson} and fingerprinted with SHA-256 at collection time so any
 * later modification can be detected.
 */
public final class Evidence {
    private Long id;
    private Long caseId;
    private final EvidenceSource source;
    private final String eventId;
    private final Instant eventTime;
    private final String eventName;
    private final String eventSource;
    private final String actor;
    private final String sourceIp;
    private final String region;
    private final String errorCode;
    private final String rawJson;
    private final String sha256;

    public Evidence(Long id, Long caseId, EvidenceSource source, String eventId, Instant eventTime,
                    String eventName, String eventSource, String actor, String sourceIp, String region,
                    String errorCode, String rawJson, String sha256) {
        this.id = id;
        this.caseId = caseId;
        this.source = Objects.requireNonNull(source);
        this.eventId = Objects.requireNonNull(eventId);
        this.eventTime = Objects.requireNonNull(eventTime);
        this.eventName = Objects.requireNonNull(eventName);
        this.eventSource = eventSource;
        this.actor = actor == null ? "unknown" : actor;
        this.sourceIp = sourceIp;
        this.region = region;
        this.errorCode = errorCode;
        this.rawJson = Objects.requireNonNull(rawJson);
        this.sha256 = Objects.requireNonNull(sha256);
    }

    public boolean isFailure() { return errorCode != null && !errorCode.isBlank(); }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Long getCaseId() { return caseId; }
    public void setCaseId(Long caseId) { this.caseId = caseId; }
    public EvidenceSource getSource() { return source; }
    public String getEventId() { return eventId; }
    public Instant getEventTime() { return eventTime; }
    public String getEventName() { return eventName; }
    public String getEventSource() { return eventSource; }
    public String getActor() { return actor; }
    public String getSourceIp() { return sourceIp; }
    public String getRegion() { return region; }
    public String getErrorCode() { return errorCode; }
    public String getRawJson() { return rawJson; }
    public String getSha256() { return sha256; }
}
