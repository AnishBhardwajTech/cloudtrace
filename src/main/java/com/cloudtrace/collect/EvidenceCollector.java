package com.cloudtrace.collect;

import com.cloudtrace.model.Evidence;

import java.time.Instant;
import java.util.List;

/** A source of AWS log evidence for a time window. */
public interface EvidenceCollector {
    List<Evidence> collect(Instant from, Instant to) throws CollectionException;

    String describe();

    class CollectionException extends Exception {
        public CollectionException(String message, Throwable cause) { super(message, cause); }
    }
}
