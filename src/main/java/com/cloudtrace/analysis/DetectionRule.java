package com.cloudtrace.analysis;

import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.Finding;
import com.cloudtrace.model.Severity;

import java.util.List;

/** A forensic detection rule evaluated over a time-ordered list of evidence. */
public interface DetectionRule {
    String id();

    String title();

    Severity severity();

    List<Finding> evaluate(List<Evidence> timeline);
}
