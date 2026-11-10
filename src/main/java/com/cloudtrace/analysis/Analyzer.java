package com.cloudtrace.analysis;

import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.Finding;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** Runs every detection rule over the case timeline and ranks the findings. */
public class Analyzer {
    private final List<DetectionRule> rules;

    public Analyzer() { this(Rules.all()); }

    public Analyzer(List<DetectionRule> rules) { this.rules = List.copyOf(rules); }

    public List<Finding> analyze(List<Evidence> evidence) {
        List<Evidence> timeline = evidence.stream().sorted(Comparator.comparing(Evidence::getEventTime)).toList();
        List<Finding> findings = new ArrayList<>();
        for (DetectionRule rule : rules) findings.addAll(rule.evaluate(timeline));
        findings.sort(Comparator.comparing((Finding f) -> -f.severity().rank()).thenComparing(Finding::firstSeen));
        return findings;
    }

    public List<DetectionRule> rules() { return rules; }
}
