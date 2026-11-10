package com.cloudtrace.model;

import java.time.Instant;
import java.util.Objects;

/** A forensic investigation: groups evidence, findings and the chain of custody. */
public class InvestigationCase {
    private Long id;
    private final String title;
    private final String description;
    private final String investigator;
    private CaseStatus status;
    private final Instant createdAt;

    public InvestigationCase(Long id, String title, String description, String investigator,
                             CaseStatus status, Instant createdAt) {
        if (title == null || title.isBlank()) throw new IllegalArgumentException("title is required");
        if (investigator == null || investigator.isBlank()) throw new IllegalArgumentException("investigator is required");
        this.id = id;
        this.title = title;
        this.description = description == null ? "" : description;
        this.investigator = investigator;
        this.status = Objects.requireNonNull(status);
        this.createdAt = Objects.requireNonNull(createdAt);
    }

    public static InvestigationCase open(String title, String description, String investigator) {
        return new InvestigationCase(null, title, description, investigator, CaseStatus.OPEN, Instant.now());
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
    public String getInvestigator() { return investigator; }
    public CaseStatus getStatus() { return status; }
    public void setStatus(CaseStatus status) { this.status = Objects.requireNonNull(status); }
    public Instant getCreatedAt() { return createdAt; }

    @Override
    public String toString() {
        return "Case #" + id + " [" + status + "] " + title + " (" + investigator + ")";
    }
}
