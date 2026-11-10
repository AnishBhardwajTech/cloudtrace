package com.cloudtrace.report;

import com.cloudtrace.TestData;
import com.cloudtrace.analysis.Analyzer;
import com.cloudtrace.model.CustodyEntry;
import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.Finding;
import com.cloudtrace.model.InvestigationCase;
import com.cloudtrace.service.IntegrityReport;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.parser.PdfTextExtractor;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PdfReportGeneratorTest {

    private static byte[] render(List<Evidence> ev, List<Finding> fs, IntegrityReport ir) throws Exception {
        InvestigationCase c = InvestigationCase.open("Compromised CI user", "Suspicious logins on dev-jenkins", "anish");
        c.setId(7L);
        Map<String, Integer> byActor = new LinkedHashMap<>();
        ev.forEach(e -> byActor.merge(e.getActor(), 1, Integer::sum));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        new PdfReportGenerator().write(new PdfReportGenerator.ReportData(c, ev, fs, byActor,
                List.of(new CustodyEntry(1L, 7, "CASE_OPENED", "anish", "Case created", Instant.now())), ir), out);
        return out.toByteArray();
    }

    @Test
    void generatesMultiPageReportWithChartsAndSections() throws Exception {
        List<Evidence> ev = TestData.sample();
        byte[] pdf = render(ev, new Analyzer().analyze(ev), new IntegrityReport(ev.size(), List.of()));
        assertEquals("%PDF", new String(pdf, 0, 4));
        PdfReader reader = new PdfReader(pdf);
        assertTrue(reader.getNumberOfPages() >= 3);
        PdfTextExtractor text = new PdfTextExtractor(reader);
        String page1 = text.getTextFromPage(1);
        assertTrue(page1.contains("Case #7"));
        assertTrue(page1.contains("VERIFIED"));
        String page2 = text.getTextFromPage(2);
        assertTrue(page2.contains("BRUTE-FORCE"));
        assertTrue(page2.contains("Chain of custody"));
        assertTrue(pdf.length > 50_000, "charts are embedded as images");
        reader.close();
    }

    @Test
    void emptyCaseAndTamperedEvidenceStillRender() throws Exception {
        byte[] pdf = render(List.of(), List.of(), new IntegrityReport(3, List.of("abc")));
        PdfReader reader = new PdfReader(pdf);
        assertTrue(new PdfTextExtractor(reader).getTextFromPage(1).contains("FAILED"));
        reader.close();
    }

    @Test
    void chartsRenderToPng() throws Exception {
        List<Evidence> ev = TestData.sample();
        byte[] png = Charts.png(Charts.activityTimeline(ev), 400, 200);
        assertEquals((byte) 0x89, png[0]);
        assertEquals('P', png[1]);
    }
}
