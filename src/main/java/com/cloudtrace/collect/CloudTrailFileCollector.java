package com.cloudtrace.collect;

import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.EvidenceSource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.GZIPInputStream;

/**
 * Imports CloudTrail log files (.json or .json.gz, as delivered to S3) from a file
 * or directory, for offline investigations of exported logs.
 */
public class CloudTrailFileCollector implements EvidenceCollector {
    private final Path path;
    private final CloudTrailRecordParser parser = new CloudTrailRecordParser();

    public CloudTrailFileCollector(Path path) { this.path = path; }

    @Override
    public List<Evidence> collect(Instant from, Instant to) throws CollectionException {
        if (!Files.exists(path)) throw new CollectionException("no such file or directory: " + path, null);
        List<Evidence> out = new ArrayList<>();
        try (Stream<Path> files = Files.isDirectory(path) ? Files.walk(path) : Stream.of(path)) {
            for (Path f : files.filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".json") || p.toString().endsWith(".json.gz"))
                    .sorted().toList()) {
                for (Evidence e : parser.parseLogFile(read(f), EvidenceSource.CLOUDTRAIL_FILE)) {
                    if ((from == null || !e.getEventTime().isBefore(from)) && (to == null || e.getEventTime().isBefore(to))) {
                        out.add(e);
                    }
                }
            }
        } catch (IOException ex) {
            throw new CollectionException("could not read CloudTrail files at " + path + ": " + ex.getMessage(), ex);
        }
        return out;
    }

    private static String read(Path f) throws IOException {
        try (InputStream in = f.toString().endsWith(".gz") ? new GZIPInputStream(Files.newInputStream(f)) : Files.newInputStream(f)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Override
    public String describe() { return "CloudTrail log files at " + path; }
}
