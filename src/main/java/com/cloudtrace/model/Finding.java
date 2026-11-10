package com.cloudtrace.model;

import java.time.Instant;
import java.util.List;

/** Suspicious activity detected by an analysis rule, linked to the evidence that proves it. */
public record Finding(Long id, Long caseId, String ruleId, String title, Severity severity,
                      String actor, Instant firstSeen, Instant lastSeen, String description,
                      List<String> evidenceEventIds) {

    public Finding {
        evidenceEventIds = List.copyOf(evidenceEventIds);
    }

    public Finding withIds(Long newId, Long newCaseId) {
        return new Finding(newId, newCaseId, ruleId, title, severity, actor, firstSeen, lastSeen,
                description, evidenceEventIds);
    }
}
