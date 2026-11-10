package com.cloudtrace.service;

import java.util.List;

/** Result of re-hashing every evidence record and comparing with the hash taken at collection. */
public record IntegrityReport(int checked, List<String> tamperedEventIds) {
    public boolean intact() { return tamperedEventIds.isEmpty(); }
}
