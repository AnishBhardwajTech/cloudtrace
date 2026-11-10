package com.cloudtrace.store;

import com.cloudtrace.model.CaseStatus;
import com.cloudtrace.model.CustodyEntry;
import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.EvidenceSource;
import com.cloudtrace.model.Finding;
import com.cloudtrace.model.InvestigationCase;
import com.cloudtrace.model.Severity;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** JDBC data access for cases, evidence, findings and the chain of custody. */
public class CaseRepository {
    private final Database db;

    public CaseRepository(Database db) { this.db = db; }

    // ---- cases ---------------------------------------------------------
    public InvestigationCase createCase(InvestigationCase c) throws SQLException {
        try (Connection con = db.connect(); PreparedStatement ps = con.prepareStatement(
                "INSERT INTO cases (title, description, investigator, status, created_at) VALUES (?, ?, ?, ?, ?)",
                Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, c.getTitle());
            ps.setString(2, c.getDescription());
            ps.setString(3, c.getInvestigator());
            ps.setString(4, c.getStatus().name());
            ps.setTimestamp(5, Timestamp.from(c.getCreatedAt()));
            ps.executeUpdate();
            try (ResultSet keys = ps.getGeneratedKeys()) {
                keys.next();
                c.setId(keys.getLong(1));
            }
        }
        return c;
    }

    public Optional<InvestigationCase> findCase(long id) throws SQLException {
        try (Connection con = db.connect(); PreparedStatement ps = con.prepareStatement(
                "SELECT id, title, description, investigator, status, created_at FROM cases WHERE id = ?")) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(mapCase(rs)) : Optional.empty();
            }
        }
    }

    public List<InvestigationCase> listCases() throws SQLException {
        List<InvestigationCase> out = new ArrayList<>();
        try (Connection con = db.connect(); PreparedStatement ps = con.prepareStatement(
                "SELECT id, title, description, investigator, status, created_at FROM cases ORDER BY id");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) out.add(mapCase(rs));
        }
        return out;
    }

    public void updateStatus(long caseId, CaseStatus status) throws SQLException {
        try (Connection con = db.connect();
             PreparedStatement ps = con.prepareStatement("UPDATE cases SET status = ? WHERE id = ?")) {
            ps.setString(1, status.name());
            ps.setLong(2, caseId);
            if (ps.executeUpdate() == 0) throw new SQLException("case " + caseId + " not found");
        }
    }

    private static InvestigationCase mapCase(ResultSet rs) throws SQLException {
        return new InvestigationCase(rs.getLong(1), rs.getString(2), rs.getString(3), rs.getString(4),
                CaseStatus.valueOf(rs.getString(5)), rs.getTimestamp(6).toInstant());
    }

    // ---- evidence ------------------------------------------------------
    /** Stores evidence in one transaction, skipping events already in the case. Returns the number added. */
    public int addEvidence(long caseId, List<Evidence> items) throws SQLException {
        int added = 0;
        try (Connection con = db.connect()) {
            con.setAutoCommit(false);
            try (PreparedStatement exists = con.prepareStatement(
                         "SELECT 1 FROM evidence WHERE case_id = ? AND event_id = ?");
                 PreparedStatement ins = con.prepareStatement(
                         "INSERT INTO evidence (case_id, source, event_id, event_time, event_name, event_source, actor, "
                                 + "source_ip, region, error_code, raw_json, sha256, collected_at) "
                                 + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", Statement.RETURN_GENERATED_KEYS)) {
                for (Evidence e : items) {
                    exists.setLong(1, caseId);
                    exists.setString(2, e.getEventId());
                    try (ResultSet rs = exists.executeQuery()) {
                        if (rs.next()) continue;
                    }
                    ins.setLong(1, caseId);
                    ins.setString(2, e.getSource().name());
                    ins.setString(3, e.getEventId());
                    ins.setTimestamp(4, Timestamp.from(e.getEventTime()));
                    ins.setString(5, e.getEventName());
                    ins.setString(6, e.getEventSource());
                    ins.setString(7, e.getActor());
                    ins.setString(8, e.getSourceIp());
                    ins.setString(9, e.getRegion());
                    ins.setString(10, e.getErrorCode());
                    ins.setString(11, e.getRawJson());
                    ins.setString(12, e.getSha256());
                    ins.setTimestamp(13, Timestamp.from(Instant.now()));
                    ins.executeUpdate();
                    try (ResultSet keys = ins.getGeneratedKeys()) {
                        keys.next();
                        e.setId(keys.getLong(1));
                    }
                    e.setCaseId(caseId);
                    added++;
                }
                con.commit();
            } catch (SQLException ex) {
                con.rollback();
                throw ex;
            }
        }
        return added;
    }

    public List<Evidence> evidence(long caseId) throws SQLException {
        List<Evidence> out = new ArrayList<>();
        try (Connection con = db.connect(); PreparedStatement ps = con.prepareStatement(
                "SELECT id, case_id, source, event_id, event_time, event_name, event_source, actor, source_ip, region, "
                        + "error_code, raw_json, sha256 FROM evidence WHERE case_id = ? ORDER BY event_time, id")) {
            ps.setLong(1, caseId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    out.add(new Evidence(rs.getLong(1), rs.getLong(2), EvidenceSource.valueOf(rs.getString(3)),
                            rs.getString(4), rs.getTimestamp(5).toInstant(), rs.getString(6), rs.getString(7),
                            rs.getString(8), rs.getString(9), rs.getString(10), rs.getString(11), rs.getString(12),
                            rs.getString(13)));
                }
            }
        }
        return out;
    }

    /** SQL aggregation used by reports: number of events per actor. */
    public Map<String, Integer> eventsByActor(long caseId) throws SQLException {
        Map<String, Integer> out = new LinkedHashMap<>();
        try (Connection con = db.connect(); PreparedStatement ps = con.prepareStatement(
                "SELECT actor, COUNT(*) AS n FROM evidence WHERE case_id = ? GROUP BY actor ORDER BY n DESC, actor")) {
            ps.setLong(1, caseId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.put(rs.getString(1), rs.getInt(2));
            }
        }
        return out;
    }

    // ---- findings ------------------------------------------------------
    public void replaceFindings(long caseId, List<Finding> findings) throws SQLException {
        try (Connection con = db.connect()) {
            con.setAutoCommit(false);
            try (PreparedStatement del = con.prepareStatement("DELETE FROM findings WHERE case_id = ?");
                 PreparedStatement ins = con.prepareStatement(
                         "INSERT INTO findings (case_id, rule_id, title, severity, actor, first_seen, last_seen, "
                                 + "description, evidence_ids) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
                del.setLong(1, caseId);
                del.executeUpdate();
                for (Finding f : findings) {
                    ins.setLong(1, caseId);
                    ins.setString(2, f.ruleId());
                    ins.setString(3, f.title());
                    ins.setString(4, f.severity().name());
                    ins.setString(5, f.actor());
                    ins.setTimestamp(6, Timestamp.from(f.firstSeen()));
                    ins.setTimestamp(7, Timestamp.from(f.lastSeen()));
                    ins.setString(8, f.description());
                    ins.setString(9, String.join(",", f.evidenceEventIds()));
                    ins.addBatch();
                }
                ins.executeBatch();
                con.commit();
            } catch (SQLException ex) {
                con.rollback();
                throw ex;
            }
        }
    }

    public List<Finding> findings(long caseId) throws SQLException {
        List<Finding> out = new ArrayList<>();
        try (Connection con = db.connect(); PreparedStatement ps = con.prepareStatement(
                "SELECT id, case_id, rule_id, title, severity, actor, first_seen, last_seen, description, evidence_ids "
                        + "FROM findings WHERE case_id = ? ORDER BY id")) {
            ps.setLong(1, caseId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String ids = rs.getString(10);
                    out.add(new Finding(rs.getLong(1), rs.getLong(2), rs.getString(3), rs.getString(4),
                            Severity.valueOf(rs.getString(5)), rs.getString(6), rs.getTimestamp(7).toInstant(),
                            rs.getTimestamp(8).toInstant(), rs.getString(9),
                            ids.isEmpty() ? List.of() : Arrays.asList(ids.split(","))));
                }
            }
        }
        return out;
    }

    // ---- chain of custody ---------------------------------------------
    public void logCustody(long caseId, String action, String actor, String details) throws SQLException {
        try (Connection con = db.connect(); PreparedStatement ps = con.prepareStatement(
                "INSERT INTO custody_log (case_id, action, actor, details, at) VALUES (?, ?, ?, ?, ?)")) {
            ps.setLong(1, caseId);
            ps.setString(2, action);
            ps.setString(3, actor);
            ps.setString(4, details);
            ps.setTimestamp(5, Timestamp.from(Instant.now()));
            ps.executeUpdate();
        }
    }

    public List<CustodyEntry> custody(long caseId) throws SQLException {
        List<CustodyEntry> out = new ArrayList<>();
        try (Connection con = db.connect(); PreparedStatement ps = con.prepareStatement(
                "SELECT id, case_id, action, actor, details, at FROM custody_log WHERE case_id = ? ORDER BY id")) {
            ps.setLong(1, caseId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    out.add(new CustodyEntry(rs.getLong(1), rs.getLong(2), rs.getString(3), rs.getString(4),
                            rs.getString(5), rs.getTimestamp(6).toInstant()));
                }
            }
        }
        return out;
    }
}
