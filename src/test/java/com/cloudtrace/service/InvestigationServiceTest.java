package com.cloudtrace.service;

import com.cloudtrace.TestData;
import com.cloudtrace.analysis.Analyzer;
import com.cloudtrace.collect.CloudTrailFileCollector;
import com.cloudtrace.model.CaseStatus;
import com.cloudtrace.model.Finding;
import com.cloudtrace.store.CaseRepository;
import com.cloudtrace.store.Database;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class InvestigationServiceTest {
    private Database db;
    private CaseRepository repo;
    private InvestigationService svc;

    @BeforeEach
    void setUp() throws Exception {
        db = TestData.h2();
        db.initSchema();
        repo = new CaseRepository(db);
        svc = new InvestigationService(repo, new Analyzer());
    }

    @Test
    void fullInvestigationIsRecordedInChainOfCustody() throws Exception {
        long id = svc.openCase("Compromised CI user", "", "anish").getId();
        assertEquals(96, svc.collect(id, new CloudTrailFileCollector(TestData.samplePath()), null, null, "anish"));
        assertEquals(CaseStatus.IN_PROGRESS, repo.findCase(id).orElseThrow().getStatus());
        List<Finding> findings = svc.analyze(id, "anish");
        assertEquals(8, findings.stream().map(Finding::ruleId).distinct().count());
        assertTrue(svc.verifyIntegrity(id, "anish").intact());
        svc.closeCase(id, "anish");
        assertEquals(List.of("CASE_OPENED", "EVIDENCE_COLLECTED", "ANALYZED", "INTEGRITY_VERIFIED", "CASE_CLOSED"),
                repo.custody(id).stream().map(c -> c.action()).toList());
    }

    @Test
    void detectsTamperedEvidence() throws Exception {
        long id = svc.openCase("t", "", "anish").getId();
        svc.collect(id, new CloudTrailFileCollector(TestData.samplePath()), null, null, "anish");
        String victim = repo.evidence(id).get(10).getEventId();
        try (Connection c = db.connect(); PreparedStatement ps = c.prepareStatement(
                "UPDATE evidence SET raw_json = REPLACE(raw_json, 'us-east-1', 'eu-west-1') WHERE event_id = ?")) {
            ps.setString(1, victim);
            assertEquals(1, ps.executeUpdate());
        }
        IntegrityReport r = svc.verifyIntegrity(id, "anish");
        assertFalse(r.intact());
        assertEquals(List.of(victim), r.tamperedEventIds());
    }

    @Test
    void closedCaseRejectsNewEvidence() throws Exception {
        long id = svc.openCase("t", "", "anish").getId();
        svc.closeCase(id, "anish");
        assertThrows(IllegalStateException.class,
                () -> svc.collect(id, new CloudTrailFileCollector(TestData.samplePath()), null, null, "anish"));
        assertThrows(IllegalArgumentException.class, () -> svc.analyze(12345, "anish"));
    }

    @Test
    void caseValidation() {
        assertThrows(IllegalArgumentException.class, () -> svc.openCase(" ", "", "anish"));
        assertThrows(IllegalArgumentException.class, () -> svc.openCase("t", "", ""));
    }
}
