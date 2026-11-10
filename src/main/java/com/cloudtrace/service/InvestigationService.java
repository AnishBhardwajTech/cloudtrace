package com.cloudtrace.service;

import com.cloudtrace.analysis.Analyzer;
import com.cloudtrace.collect.EvidenceCollector;
import com.cloudtrace.collect.Hashing;
import com.cloudtrace.model.CaseStatus;
import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.Finding;
import com.cloudtrace.model.InvestigationCase;
import com.cloudtrace.store.CaseRepository;

import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** Orchestrates an investigation and records every step in the chain of custody. */
public class InvestigationService {
    private final CaseRepository repo;
    private final Analyzer analyzer;

    public InvestigationService(CaseRepository repo, Analyzer analyzer) {
        this.repo = repo;
        this.analyzer = analyzer;
    }

    public InvestigationCase openCase(String title, String description, String investigator) throws SQLException {
        InvestigationCase c = repo.createCase(InvestigationCase.open(title, description, investigator));
        repo.logCustody(c.getId(), "CASE_OPENED", investigator, "Case created: " + title);
        return c;
    }

    public int collect(long caseId, EvidenceCollector collector, Instant from, Instant to, String investigator)
            throws SQLException, EvidenceCollector.CollectionException {
        InvestigationCase c = requireOpen(caseId);
        List<Evidence> items = collector.collect(from, to);
        int added = repo.addEvidence(caseId, items);
        repo.logCustody(caseId, "EVIDENCE_COLLECTED", investigator, String.format(
                "%d new of %d events from %s, %s (SHA-256 recorded per event)",
                added, items.size(), collector.describe(),
                from == null && to == null ? "full time range" : "window " + from + " to " + to));
        if (c.getStatus() == CaseStatus.OPEN) repo.updateStatus(caseId, CaseStatus.IN_PROGRESS);
        return added;
    }

    public List<Finding> analyze(long caseId, String investigator) throws SQLException {
        requireCase(caseId);
        List<Finding> findings = analyzer.analyze(repo.evidence(caseId));
        repo.replaceFindings(caseId, findings);
        repo.logCustody(caseId, "ANALYZED", investigator,
                findings.size() + " findings from " + analyzer.rules().size() + " rules");
        return repo.findings(caseId);
    }

    public IntegrityReport verifyIntegrity(long caseId, String investigator) throws SQLException {
        requireCase(caseId);
        List<String> tampered = new ArrayList<>();
        List<Evidence> all = repo.evidence(caseId);
        for (Evidence e : all) {
            if (!Hashing.sha256(e.getRawJson()).equals(e.getSha256())) tampered.add(e.getEventId());
        }
        IntegrityReport r = new IntegrityReport(all.size(), List.copyOf(tampered));
        repo.logCustody(caseId, "INTEGRITY_VERIFIED", investigator,
                r.intact() ? "All " + r.checked() + " records match their hashes"
                        : r.tamperedEventIds().size() + " record(s) FAILED verification");
        return r;
    }

    public void closeCase(long caseId, String investigator) throws SQLException {
        requireCase(caseId);
        repo.updateStatus(caseId, CaseStatus.CLOSED);
        repo.logCustody(caseId, "CASE_CLOSED", investigator, "Case closed");
    }

    public void recordReport(long caseId, String investigator, String path, String sha256) throws SQLException {
        repo.logCustody(caseId, "REPORT_GENERATED", investigator, path + " sha256=" + sha256);
    }

    private InvestigationCase requireCase(long caseId) throws SQLException {
        return repo.findCase(caseId).orElseThrow(() -> new IllegalArgumentException("case " + caseId + " not found"));
    }

    private InvestigationCase requireOpen(long caseId) throws SQLException {
        InvestigationCase c = requireCase(caseId);
        if (c.getStatus() == CaseStatus.CLOSED) throw new IllegalStateException("case " + caseId + " is closed");
        return c;
    }
}
