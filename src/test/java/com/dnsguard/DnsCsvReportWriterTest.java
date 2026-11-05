package com.dnsguard;

import com.dnsguard.model.DnsAlert;
import com.dnsguard.model.DnsQuery;
import com.dnsguard.report.DnsCsvReportWriter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DnsCsvReportWriterTest {

    @TempDir
    Path tempDir;

    @Test
    void writesHeaderAndAlertToCsv() throws IOException {
        Path output = tempDir.resolve("reports/alerts.csv");

        DnsQuery query = new DnsQuery(
                Instant.parse("2026-10-24T10:00:00Z"),
                "192.168.1.20",
                "example.com",
                "TXT",
                "NOERROR"
        );

        DnsAlert alert = new DnsAlert(
                query,
                80,
                List.of("Unusually long domain",
                        "High-entropy first label")
        );

        DnsCsvReportWriter writer = new DnsCsvReportWriter();
        writer.write(output, List.of(alert));

        assertTrue(Files.exists(output));

        List<String> lines = Files.readAllLines(output);

        assertEquals(2, lines.size());
        assertTrue(lines.get(0).contains("timestamp,sourceIp,domain"));
        assertTrue(lines.get(1).contains("192.168.1.20"));
        assertTrue(lines.get(1).contains("example.com"));
        assertTrue(lines.get(1).contains("80"));
        assertTrue(lines.get(1).contains("HIGH"));
    }

    @Test
    void escapesCommasAndQuotesInCsvFields() throws IOException {
        Path output = tempDir.resolve("escaped.csv");

        DnsQuery query = new DnsQuery(
                Instant.parse("2026-10-24T10:00:00Z"),
                "192.168.1.21",
                "test.example.com",
                "TXT",
                "NOERROR"
        );

        DnsAlert alert = new DnsAlert(
                query,
                50,
                List.of("Suspicious, label contains \"quotes\"")
        );

        new DnsCsvReportWriter().write(output, List.of(alert));

        String contents = Files.readString(output);

        assertTrue(contents.contains(
                "\"Suspicious, label contains \"\"quotes\"\"\""));
    }

    @Test
    void writesHeaderWhenThereAreNoAlerts() throws IOException {
        Path output = tempDir.resolve("empty.csv");

        new DnsCsvReportWriter().write(output, List.of());

        List<String> lines = Files.readAllLines(output);

        assertEquals(1, lines.size());
        assertTrue(lines.get(0).startsWith("timestamp,sourceIp,domain"));
    }
}
