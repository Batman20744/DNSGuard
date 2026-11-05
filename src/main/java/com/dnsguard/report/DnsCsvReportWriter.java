package com.dnsguard.report;

import com.dnsguard.model.DnsAlert;
import com.dnsguard.model.DnsQuery;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

public class DnsCsvReportWriter {

    private static final String HEADER =
            "timestamp,sourceIp,domain,recordType,responseCode,"
                    + "riskScore,severity,reasons";

    public void write(Path outputFile, List<DnsAlert> alerts)
            throws IOException {

        if (outputFile == null) {
            throw new IllegalArgumentException(
                    "Output file path cannot be null");
        }

        if (alerts == null) {
            throw new IllegalArgumentException(
                    "Alert list cannot be null");
        }

        Path absolutePath = outputFile.toAbsolutePath();
        Path parent = absolutePath.getParent();

        if (parent != null) {
            Files.createDirectories(parent);
        }

        try (BufferedWriter writer = Files.newBufferedWriter(
                absolutePath,
                StandardCharsets.UTF_8)) {

            writer.write(HEADER);
            writer.newLine();

            for (DnsAlert alert : alerts) {
                if (alert == null) {
                    continue;
                }

                DnsQuery query = alert.getQuery();

                String reasons = alert.getReasons().stream()
                        .collect(Collectors.joining("; "));

                String row = String.join(",",
                        escape(query.getTimestamp().toString()),
                        escape(query.getSourceIp()),
                        escape(query.getDomain()),
                        escape(query.getRecordType()),
                        escape(query.getResponseCode()),
                        escape(Integer.toString(alert.getRiskScore())),
                        escape(alert.getSeverity().toString()),
                        escape(reasons)
                );

                writer.write(row);
                writer.newLine();
            }
        }
    }

    private String escape(String value) {
        if (value == null) {
            return "";
        }

        if (value.contains(",")
                || value.contains("\"")
                || value.contains("\n")
                || value.contains("\r")) {

            return "\"" + value.replace("\"", "\"\"") + "\"";
        }

        return value;
    }
}
