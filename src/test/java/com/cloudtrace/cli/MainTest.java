package com.cloudtrace.cli;

import com.cloudtrace.TestData;
import com.cloudtrace.store.Database;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class MainTest {

    @Test
    void endToEnd(@TempDir Path dir) throws Exception {
        Database db = TestData.h2();
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        Main cli = new Main(db, new PrintStream(buf));

        assertEquals(0, cli.run(new String[]{"case-open", "--title", "Incident 42", "--investigator", "anish"}));
        assertEquals(0, cli.run(new String[]{"import", "--case", "1", "--path", TestData.samplePath().toString()}));
        assertEquals(0, cli.run(new String[]{"analyze", "--case", "1"}));
        assertEquals(0, cli.run(new String[]{"verify", "--case", "1"}));
        Path pdf = dir.resolve("case1.pdf");
        assertEquals(0, cli.run(new String[]{"report", "--case", "1", "--out", pdf.toString()}));
        assertEquals(0, cli.run(new String[]{"case-list"}));
        assertEquals(0, cli.run(new String[]{"close", "--case", "1"}));

        String out = buf.toString();
        assertTrue(out.contains("Imported 96 new evidence records"));
        assertTrue(out.contains("BRUTE-FORCE"));
        assertTrue(out.contains("all 96 evidence hashes verified"));
        assertTrue(Files.size(pdf) > 50_000);
    }

    @Test
    void errors() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        Main cli = new Main(TestData.h2(), new PrintStream(buf));
        assertEquals(1, cli.run(new String[]{}));
        assertEquals(1, cli.run(new String[]{"bogus"}));
        assertEquals(1, cli.run(new String[]{"analyze"}));
        assertEquals(1, cli.run(new String[]{"analyze", "--case", "x"}));
        assertEquals(1, cli.run(new String[]{"analyze", "--case", "99"}));
        assertTrue(buf.toString().contains("--case is required"));
    }
}
