package com.cloudtrace.store;

import com.cloudtrace.TestData;
import com.cloudtrace.analysis.Analyzer;
import com.cloudtrace.model.CaseStatus;
import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.Finding;
import com.cloudtrace.model.InvestigationCase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** The same repository tests, run against H2 (always) and MySQL (when configured). */
abstract class RepositoryContract {
    protected CaseRepository repo;

    protected abstract Database database() throws Exception;

    @BeforeEach
    void setUp() throws Exception {
        Database db = database();
        db.initSchema();
        db.initSchema(); // idempotent
        repo = new CaseRepository(db);
    }

    @Test
    void createFindListAndUpdateCase() throws SQLException {
        InvestigationCase c = repo.createCase(InvestigationCase.open("Leaked key", "desc", "anish"));
        assertNotNull(c.getId());
        InvestigationCase loaded = repo.findCase(c.getId()).orElseThrow();
        assertEquals("Leaked key", loaded.getTitle());
        assertEquals(CaseStatus.OPEN, loaded.getStatus());
        repo.updateStatus(c.getId(), CaseStatus.CLOSED);
        assertEquals(CaseStatus.CLOSED, repo.findCase(c.getId()).orElseThrow().getStatus());
        assertTrue(repo.listCases().stream().anyMatch(x -> x.getId().equals(c.getId())));
        assertThrows(SQLException.class, () -> repo.updateStatus(999_999, CaseStatus.OPEN));
    }

    @Test
    void evidenceIsStoredOnceAndRoundTrips() throws SQLException {
        long id = repo.createCase(InvestigationCase.open("t", "", "anish")).getId();
        List<Evidence> sample = TestData.sample();
        assertEquals(96, repo.addEvidence(id, sample));
        assertEquals(0, repo.addEvidence(id, TestData.sample()), "re-importing the same events adds nothing");

        List<Evidence> stored = repo.evidence(id);
        assertEquals(96, stored.size());
        Evidence first = stored.get(0);
        Evidence original = sample.stream().filter(e -> e.getEventId().equals(first.getEventId())).findFirst().orElseThrow();
        assertEquals(original.getRawJson(), first.getRawJson());
        assertEquals(original.getSha256(), first.getSha256());
        assertEquals(original.getEventTime(), first.getEventTime());

        Map<String, Integer> byActor = repo.eventsByActor(id);
        assertEquals("dev-jenkins", byActor.keySet().iterator().next());
        assertEquals(96, byActor.values().stream().mapToInt(Integer::intValue).sum());
    }

    @Test
    void findingsAndCustody() throws SQLException {
        long id = repo.createCase(InvestigationCase.open("t", "", "anish")).getId();
        List<Finding> fs = new Analyzer().analyze(TestData.sample());
        repo.replaceFindings(id, fs);
        repo.replaceFindings(id, fs); // replace, not append
        List<Finding> stored = repo.findings(id);
        assertEquals(fs.size(), stored.size());
        assertEquals(fs.get(0).evidenceEventIds(), stored.get(0).evidenceEventIds());

        repo.logCustody(id, "CASE_OPENED", "anish", "x");
        repo.logCustody(id, "ANALYZED", "anish", "y");
        assertEquals(List.of("CASE_OPENED", "ANALYZED"), repo.custody(id).stream().map(c -> c.action()).toList());
    }
}
