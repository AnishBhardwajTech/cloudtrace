package com.cloudtrace.collect;

import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.EvidenceSource;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/** Turns CloudTrail JSON records into {@link Evidence}, hashing each original record. */
public class CloudTrailRecordParser {
    private final ObjectMapper mapper = new ObjectMapper();

    /** Parses a CloudTrail log file body: {"Records": [ ... ]}. */
    public List<Evidence> parseLogFile(String json, EvidenceSource source) throws IOException {
        JsonNode root = mapper.readTree(json);
        JsonNode records = root.path("Records");
        if (!records.isArray()) throw new IOException("not a CloudTrail log file: missing Records array");
        List<Evidence> out = new ArrayList<>();
        for (JsonNode r : records) out.add(toEvidence(r, source));
        return out;
    }

    /** Parses a single record, e.g. the CloudTrailEvent string returned by LookupEvents. */
    public Evidence parseRecord(String json, EvidenceSource source) throws IOException {
        return toEvidence(mapper.readTree(json), source);
    }

    Evidence toEvidence(JsonNode r, EvidenceSource source) throws IOException {
        String raw = mapper.writeValueAsString(r); // canonical compact form, hashed below
        String eventName = text(r, "eventName");
        String time = text(r, "eventTime");
        if (eventName == null || time == null) throw new IOException("record missing eventName/eventTime");
        String eventId = text(r, "eventID");
        return new Evidence(null, null, source,
                eventId != null ? eventId : UUID.nameUUIDFromBytes(raw.getBytes()).toString(),
                Instant.parse(time), eventName, text(r, "eventSource"), actor(r.path("userIdentity")),
                text(r, "sourceIPAddress"), text(r, "awsRegion"), text(r, "errorCode"), raw, Hashing.sha256(raw));
    }

    /** Human-readable identity: root, IAM user name, or assumed-role session. */
    static String actor(JsonNode id) {
        String type = text(id, "type");
        if ("Root".equals(type)) return "root";
        if (text(id, "userName") != null) return text(id, "userName");
        String arn = text(id, "arn");
        if (arn != null) {
            int slash = arn.indexOf('/');
            return slash > 0 ? arn.substring(slash + 1) : arn; // e.g. "admin-role/session-name"
        }
        String invokedBy = text(id, "invokedBy");
        return invokedBy != null ? invokedBy : (type != null ? type : "unknown");
    }

    private static String text(JsonNode n, String field) {
        JsonNode v = n.path(field);
        return v.isMissingNode() || v.isNull() ? null : v.asText();
    }
}
