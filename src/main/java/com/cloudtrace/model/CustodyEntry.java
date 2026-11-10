package com.cloudtrace.model;

import java.time.Instant;

/** One link in the chain of custody: who did what with the evidence, and when. */
public record CustodyEntry(Long id, long caseId, String action, String actor, String details, Instant at) {}
