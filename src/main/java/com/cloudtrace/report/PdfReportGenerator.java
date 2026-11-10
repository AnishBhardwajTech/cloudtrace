package com.cloudtrace.report;

import com.cloudtrace.model.CustodyEntry;
import com.cloudtrace.model.Evidence;
import com.cloudtrace.model.Finding;
import com.cloudtrace.model.InvestigationCase;
import com.cloudtrace.service.IntegrityReport;
import com.lowagie.text.Chunk;
import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.Image;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;

import java.awt.Color;
import java.io.IOException;
import java.io.OutputStream;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/** Writes the forensic case report as a PDF (OpenPDF) with embedded JFreeChart charts. */
public class PdfReportGenerator {
    static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC);
    static final int EVIDENCE_APPENDIX_LIMIT = 200;
    private static final Font H1 = new Font(Font.HELVETICA, 20, Font.BOLD);
    private static final Font H2 = new Font(Font.HELVETICA, 14, Font.BOLD, new Color(0x1E293B));
    private static final Font BODY = new Font(Font.HELVETICA, 10);
    private static final Font SMALL = new Font(Font.HELVETICA, 8);
    private static final Font MONO = new Font(Font.COURIER, 7);
    private static final Font TH = new Font(Font.HELVETICA, 9, Font.BOLD, Color.WHITE);

    public record ReportData(InvestigationCase investigation, List<Evidence> evidence, List<Finding> findings,
                             Map<String, Integer> eventsByActor, List<CustodyEntry> custody,
                             IntegrityReport integrity) {}

    public void write(ReportData d, OutputStream out) throws IOException {
        Document doc = new Document(PageSize.A4, 40, 40, 40, 40);
        try {
            PdfWriter.getInstance(doc, out);
            doc.addTitle("CloudTrace report - case " + d.investigation().getId());
            doc.addAuthor(d.investigation().getInvestigator());
            doc.open();
            header(doc, d);
            summary(doc, d);
            charts(doc, d);
            findings(doc, d.findings());
            custody(doc, d.custody());
            evidenceAppendix(doc, d.evidence());
        } catch (DocumentException e) {
            throw new IOException("PDF generation failed", e);
        } finally {
            if (doc.isOpen()) doc.close();
        }
    }

    private void header(Document doc, ReportData d) throws DocumentException {
        InvestigationCase c = d.investigation();
        doc.add(new Paragraph("CloudTrace Forensic Report", H1));
        doc.add(new Paragraph("Case #" + c.getId() + ": " + c.getTitle(), H2));
        doc.add(new Paragraph(String.format("Investigator: %s    Status: %s    Opened: %s",
                c.getInvestigator(), c.getStatus(), TS.format(c.getCreatedAt())), BODY));
        if (!c.getDescription().isBlank()) doc.add(new Paragraph(c.getDescription(), BODY));
        doc.add(Chunk.NEWLINE);
    }

    private void summary(Document doc, ReportData d) throws DocumentException {
        doc.add(heading("Summary"));
        PdfPTable t = new PdfPTable(2);
        t.setWidthPercentage(60);
        t.setHorizontalAlignment(Element.ALIGN_LEFT);
        row(t, "Evidence records", String.valueOf(d.evidence().size()));
        if (!d.evidence().isEmpty()) {
            row(t, "Time span", TS.format(d.evidence().get(0).getEventTime()) + " to "
                    + TS.format(d.evidence().get(d.evidence().size() - 1).getEventTime()));
        }
        row(t, "Distinct actors", String.valueOf(d.eventsByActor().size()));
        row(t, "Findings", String.valueOf(d.findings().size()));
        IntegrityReport ir = d.integrity();
        row(t, "Evidence integrity", ir.intact() ? "VERIFIED (" + ir.checked() + " SHA-256 hashes match)"
                : "FAILED: " + ir.tamperedEventIds().size() + " record(s) altered");
        doc.add(t);
        doc.add(Chunk.NEWLINE);
    }

    private void charts(Document doc, ReportData d) throws DocumentException, IOException {
        if (d.evidence().isEmpty()) return;
        addChart(doc, Charts.png(Charts.activityTimeline(d.evidence()), 1000, 420));
        PdfPTable two = new PdfPTable(2);
        two.setWidthPercentage(100);
        two.addCell(chartCell(Charts.png(Charts.eventsByActor(d.eventsByActor()), 600, 450)));
        two.addCell(d.findings().isEmpty() ? new PdfPCell(new Phrase("No findings", BODY))
                : chartCell(Charts.png(Charts.findingsBySeverity(d.findings()), 600, 450)));
        doc.add(two);
    }

    private void findings(Document doc, List<Finding> findings) throws DocumentException {
        doc.newPage();
        doc.add(heading("Findings"));
        if (findings.isEmpty()) {
            doc.add(new Paragraph("No suspicious activity detected by the rule set.", BODY));
            return;
        }
        PdfPTable t = table(new float[]{1.1f, 1.6f, 1.4f, 2.2f, 4.5f}, "Severity", "Rule", "Actor", "When", "Details");
        for (Finding f : findings) {
            PdfPCell sev = new PdfPCell(new Phrase(f.severity().name(), TH));
            sev.setBackgroundColor(Charts.COLORS.get(f.severity()));
            t.addCell(sev);
            t.addCell(new Phrase(f.ruleId() + "\n" + f.title(), SMALL));
            t.addCell(new Phrase(f.actor(), SMALL));
            t.addCell(new Phrase(TS.format(f.firstSeen()) + "\nto " + TS.format(f.lastSeen()), SMALL));
            t.addCell(new Phrase(f.description() + "\nEvidence: " + f.evidenceEventIds().size() + " event(s)", SMALL));
        }
        doc.add(t);
    }

    private void custody(Document doc, List<CustodyEntry> custody) throws DocumentException {
        doc.add(Chunk.NEWLINE);
        doc.add(heading("Chain of custody"));
        PdfPTable t = table(new float[]{2.2f, 2f, 1.5f, 5f}, "Time", "Action", "By", "Details");
        for (CustodyEntry c : custody) {
            t.addCell(new Phrase(TS.format(c.at()), SMALL));
            t.addCell(new Phrase(c.action(), SMALL));
            t.addCell(new Phrase(c.actor(), SMALL));
            t.addCell(new Phrase(c.details(), SMALL));
        }
        doc.add(t);
    }

    private void evidenceAppendix(Document doc, List<Evidence> evidence) throws DocumentException {
        doc.newPage();
        doc.add(heading("Appendix: evidence log"));
        if (evidence.size() > EVIDENCE_APPENDIX_LIMIT) {
            doc.add(new Paragraph("Showing the first " + EVIDENCE_APPENDIX_LIMIT + " of " + evidence.size()
                    + " records. All records are preserved in the case database.", SMALL));
        }
        PdfPTable t = table(new float[]{2f, 2f, 1.6f, 1.4f, 1.2f, 3.6f}, "Time", "Event", "Actor", "Source IP", "Result", "SHA-256");
        for (Evidence e : evidence.stream().limit(EVIDENCE_APPENDIX_LIMIT).toList()) {
            t.addCell(new Phrase(TS.format(e.getEventTime()), SMALL));
            t.addCell(new Phrase(e.getEventName(), SMALL));
            t.addCell(new Phrase(e.getActor(), SMALL));
            t.addCell(new Phrase(e.getSourceIp() == null ? "" : e.getSourceIp(), SMALL));
            t.addCell(new Phrase(e.isFailure() ? e.getErrorCode() : "OK", SMALL));
            t.addCell(new Phrase(e.getSha256(), MONO));
        }
        doc.add(t);
    }

    // ---- helpers -------------------------------------------------------
    private static Paragraph heading(String text) {
        Paragraph p = new Paragraph(text, H2);
        p.setSpacingBefore(4);
        p.setSpacingAfter(8);
        return p;
    }

    private static void row(PdfPTable t, String k, String v) {
        PdfPCell kc = new PdfPCell(new Phrase(k, new Font(Font.HELVETICA, 10, Font.BOLD)));
        kc.setBackgroundColor(new Color(0xF1F5F9));
        t.addCell(kc);
        t.addCell(new Phrase(v, BODY));
    }

    private static PdfPTable table(float[] widths, String... headers) {
        PdfPTable t = new PdfPTable(widths);
        t.setWidthPercentage(100);
        t.setHeaderRows(1);
        for (String h : headers) {
            PdfPCell c = new PdfPCell(new Phrase(h, TH));
            c.setBackgroundColor(new Color(0x1E293B));
            c.setPadding(4);
            t.addCell(c);
        }
        return t;
    }

    private static void addChart(Document doc, byte[] png) throws DocumentException, IOException {
        Image img = Image.getInstance(png);
        img.scaleToFit(PageSize.A4.getWidth() - 80, 300);
        doc.add(img);
    }

    private static PdfPCell chartCell(byte[] png) throws IOException {
        Image img = Image.getInstance(png);
        PdfPCell c = new PdfPCell(img, true);
        c.setBorder(0);
        return c;
    }
}
