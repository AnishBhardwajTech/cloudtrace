package com.cloudtrace.analysis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Small helper to read nested fields from an evidence record's original JSON. */
final class Json {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Json() {}

    static JsonNode parse(String raw) {
        try {
            return MAPPER.readTree(raw);
        } catch (Exception e) {
            return MAPPER.createObjectNode();
        }
    }

    /** Dotted path lookup, e.g. "additionalEventData.MFAUsed". Returns "" when absent. */
    static String at(JsonNode root, String path) {
        JsonNode n = root;
        for (String part : path.split("\\.")) n = n.path(part);
        return n.isMissingNode() || n.isNull() ? "" : (n.isValueNode() ? n.asText() : n.toString());
    }
}
