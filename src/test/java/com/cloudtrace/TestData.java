package com.cloudtrace;

import com.cloudtrace.collect.CloudTrailFileCollector;
import com.cloudtrace.collect.CloudTrailRecordParser;
import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.EvidenceSource;
import com.cloudtrace.store.Database;

import java.net.URISyntaxException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class TestData {
    private TestData() {}

    public static Path samplePath() {
        try {
            return Path.of(TestData.class.getResource("/cloudtrail-incident.json").toURI());
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }

    public static List<Evidence> sample() {
        try {
            return new CloudTrailFileCollector(samplePath()).collect(null, null);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static Database h2() {
        return new Database("jdbc:h2:mem:ct" + UUID.randomUUID() + ";MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE", "sa", "");
    }

    /** Builds one evidence record from a minimal CloudTrail JSON body. */
    public static Evidence event(String user, String eventName, String time, String extraJson) {
        String identity = "root".equals(user)
                ? "{\"type\":\"Root\",\"arn\":\"arn:aws:iam::1:root\"}"
                : "{\"type\":\"IAMUser\",\"userName\":\"" + user + "\"}";
        String json = "{\"eventID\":\"" + UUID.randomUUID() + "\",\"eventName\":\"" + eventName + "\",\"eventTime\":\""
                + time + "\",\"eventSource\":\"test.amazonaws.com\",\"awsRegion\":\"us-east-1\",\"userIdentity\":"
                + identity + (extraJson == null || extraJson.isEmpty() ? "" : "," + extraJson) + "}";
        try {
            return new CloudTrailRecordParser().parseRecord(json, EvidenceSource.CLOUDTRAIL_FILE);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String at(int minute, int second) {
        return Instant.parse("2026-10-14T09:00:00Z").plusSeconds(minute * 60L + second).toString();
    }
}
