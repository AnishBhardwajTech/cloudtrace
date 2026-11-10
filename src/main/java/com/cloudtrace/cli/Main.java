package com.cloudtrace.cli;

import com.cloudtrace.analysis.Analyzer;
import com.cloudtrace.collect.CloudTrailApiCollector;
import com.cloudtrace.collect.CloudTrailFileCollector;
import com.cloudtrace.collect.EvidenceCollector;
import com.cloudtrace.collect.Hashing;
import com.cloudtrace.model.Finding;
import com.cloudtrace.model.InvestigationCase;
import com.cloudtrace.report.PdfReportGenerator;
import com.cloudtrace.service.IntegrityReport;
import com.cloudtrace.service.InvestigationService;
import com.cloudtrace.store.CaseRepository;
import com.cloudtrace.store.Database;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * cloudtrace <command> [--options]
 *
 *   case-open  --title T --investigator NAME [--description D]
 *   case-list
 *   import     --case ID --path FILE_OR_DIR          (CloudTrail .json / .json.gz files)
 *   collect    --case ID [--hours 24] [--user NAME] [--region us-east-1]   (live AWS API)
 *   analyze    --case ID
 *   verify     --case ID
 *   report     --case ID --out report.pdf
 *   close      --case ID
 */
public class Main {
    private final Database db;
    private final PrintStream out;

    public Main(Database db, PrintStream out) {
        this.db = db;
        this.out = out;
    }

    public static void main(String[] args) {
        System.setProperty("java.awt.headless", "true");
        int code = new Main(Database.fromEnv(), System.out).run(args);
        System.exit(code);
    }

    public int run(String[] args) {
        if (args.length == 0) {
            out.println("usage: cloudtrace <case-open|case-list|import|collect|analyze|verify|report|close> [--options]");
            return 1;
        }
        Map<String, String> o = options(args);
        String who = o.getOrDefault("investigator", System.getProperty("user.name", "investigator"));
        try {
            db.initSchema();
            CaseRepository repo = new CaseRepository(db);
            InvestigationService svc = new InvestigationService(repo, new Analyzer());
            switch (args[0]) {
                case "case-open" -> {
                    InvestigationCase c = svc.openCase(req(o, "title"), o.get("description"), req(o, "investigator"));
                    out.println("Opened " + c);
                }
                case "case-list" -> repo.listCases().forEach(out::println);
                case "import" -> {
                    long id = caseId(o);
                    int n = svc.collect(id, new CloudTrailFileCollector(Path.of(req(o, "path"))), null, null, who);
                    out.println("Imported " + n + " new evidence records into case " + id);
                }
                case "collect" -> {
                    long id = caseId(o);
                    Instant to = Instant.now();
                    Instant from = to.minus(Duration.ofHours(Long.parseLong(o.getOrDefault("hours", "24"))));
                    try (CloudTrailClient client = CloudTrailClient.builder()
                            .httpClient(UrlConnectionHttpClient.create())
                            .region(Region.of(o.getOrDefault("region", "us-east-1"))).build()) {
                        EvidenceCollector col = new CloudTrailApiCollector(client, o.get("user"));
                        out.println("Collected " + svc.collect(id, col, from, to, who) + " new evidence records");
                    }
                }
                case "analyze" -> {
                    List<Finding> fs = svc.analyze(caseId(o), who);
                    out.println(fs.size() + " finding(s)");
                    for (Finding f : fs) out.printf("  %-8s %-12s %-20s %s%n", f.severity(), f.ruleId(), f.actor(), f.description());
                }
                case "verify" -> {
                    IntegrityReport r = svc.verifyIntegrity(caseId(o), who);
                    out.println(r.intact() ? "OK: all " + r.checked() + " evidence hashes verified"
                            : "TAMPERED: " + r.tamperedEventIds());
                    return r.intact() ? 0 : 3;
                }
                case "report" -> {
                    long id = caseId(o);
                    Path path = Path.of(req(o, "out"));
                    InvestigationCase c = repo.findCase(id).orElseThrow(() -> new IllegalArgumentException("case " + id + " not found"));
                    IntegrityReport integrity = svc.verifyIntegrity(id, who);
                    ByteArrayOutputStream buf = new ByteArrayOutputStream();
                    new PdfReportGenerator().write(new PdfReportGenerator.ReportData(c, repo.evidence(id), repo.findings(id),
                            repo.eventsByActor(id), repo.custody(id), integrity), buf);
                    Files.write(path, buf.toByteArray());
                    String hash = Hashing.sha256(buf.toByteArray());
                    svc.recordReport(id, who, path.toString(), hash);
                    out.println("Report written to " + path);
                }
                case "close" -> {
                    svc.closeCase(caseId(o), who);
                    out.println("Case closed");
                }
                default -> {
                    out.println("unknown command: " + args[0]);
                    return 1;
                }
            }
            return 0;
        } catch (IllegalArgumentException | IllegalStateException e) {
            out.println("Error: " + e.getMessage());
            return 1;
        } catch (Exception e) {
            out.println("Error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return 2;
        }
    }

    static Map<String, String> options(String[] args) {
        Map<String, String> m = new HashMap<>();
        for (int i = 1; i < args.length; i++) {
            if (args[i].startsWith("--")) {
                String key = args[i].substring(2);
                String val = i + 1 < args.length && !args[i + 1].startsWith("--") ? args[++i] : "true";
                m.put(key, val);
            }
        }
        return m;
    }

    private static String req(Map<String, String> o, String key) {
        String v = o.get(key);
        if (v == null || v.isBlank()) throw new IllegalArgumentException("--" + key + " is required");
        return v;
    }

    private static long caseId(Map<String, String> o) {
        try {
            return Long.parseLong(req(o, "case"));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("--case must be a number");
        }
    }
}
