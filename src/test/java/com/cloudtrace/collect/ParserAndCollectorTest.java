package com.cloudtrace.collect;

import com.cloudtrace.TestData;
import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.EvidenceSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class ParserAndCollectorTest {
    private final CloudTrailRecordParser parser = new CloudTrailRecordParser();

    @Test
    void sha256KnownValue() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Hashing.sha256("abc"));
    }

    @Test
    void parsesIamUserRecord() throws IOException {
        Evidence e = parser.parseRecord("""
                {"eventID":"e1","eventTime":"2026-10-14T09:00:00Z","eventName":"CreateUser",
                 "eventSource":"iam.amazonaws.com","awsRegion":"us-east-1","sourceIPAddress":"1.2.3.4",
                 "userIdentity":{"type":"IAMUser","userName":"alice"}}""", EvidenceSource.CLOUDTRAIL_FILE);
        assertEquals("e1", e.getEventId());
        assertEquals("alice", e.getActor());
        assertEquals("1.2.3.4", e.getSourceIp());
        assertEquals(Instant.parse("2026-10-14T09:00:00Z"), e.getEventTime());
        assertFalse(e.isFailure());
        assertEquals(Hashing.sha256(e.getRawJson()), e.getSha256());
    }

    @Test
    void actorForRootAndAssumedRole() throws IOException {
        Evidence root = parser.parseRecord("{\"eventTime\":\"2026-01-01T00:00:00Z\",\"eventName\":\"X\","
                + "\"userIdentity\":{\"type\":\"Root\"}}", EvidenceSource.CLOUDTRAIL_FILE);
        Evidence role = parser.parseRecord("{\"eventTime\":\"2026-01-01T00:00:00Z\",\"eventName\":\"X\","
                + "\"userIdentity\":{\"type\":\"AssumedRole\",\"arn\":\"arn:aws:sts::1:assumed-role/deploy/gha\"}}",
                EvidenceSource.CLOUDTRAIL_FILE);
        assertEquals("root", root.getActor());
        assertEquals("deploy/gha", role.getActor());
        assertNotNull(root.getEventId(), "a stable id is derived when eventID is missing");
    }

    @Test
    void rejectsInvalidInput() {
        assertThrows(IOException.class, () -> parser.parseRecord("{\"eventName\":\"X\"}", EvidenceSource.CLOUDTRAIL_FILE));
        assertThrows(IOException.class, () -> parser.parseLogFile("{\"foo\":[]}", EvidenceSource.CLOUDTRAIL_FILE));
    }

    @Test
    void readsSampleFile() {
        List<Evidence> all = TestData.sample();
        assertEquals(96, all.size());
        assertTrue(all.stream().anyMatch(e -> e.getActor().equals("dev-jenkins")));
    }

    @Test
    void readsGzipDirectoryAndFiltersByTime(@TempDir Path dir) throws Exception {
        Path gz = dir.resolve("logs/111122223333_CloudTrail_us-east-1.json.gz");
        Files.createDirectories(gz.getParent());
        try (OutputStream out = new GZIPOutputStream(Files.newOutputStream(gz))) {
            out.write(Files.readAllBytes(TestData.samplePath()));
        }
        Files.writeString(dir.resolve("notes.txt"), "ignored");
        Instant from = Instant.parse("2026-10-14T09:00:00Z");
        Instant to = Instant.parse("2026-10-14T10:00:00Z");
        List<Evidence> window = new CloudTrailFileCollector(dir).collect(from, to);
        assertFalse(window.isEmpty());
        assertTrue(window.stream().allMatch(e -> !e.getEventTime().isBefore(from) && e.getEventTime().isBefore(to)));
    }

    @Test
    void missingPathIsCollectionError(@TempDir Path dir) {
        assertThrows(EvidenceCollector.CollectionException.class,
                () -> new CloudTrailFileCollector(dir.resolve("nope.json")).collect(null, null));
    }
}
