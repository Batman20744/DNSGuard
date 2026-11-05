
package com.dnsguard.parser;

import com.dnsguard.model.DnsQuery;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

public class DnsCsvParser {

    public List<DnsQuery> parse(Path filePath) throws IOException {
        List<DnsQuery> queries = new ArrayList<>();

        try (BufferedReader reader = Files.newBufferedReader(filePath)) {
            String header = reader.readLine();

            if (header == null ||
                    !header.trim().equalsIgnoreCase(
                            "timestamp,sourceIp,domain,recordType,responseCode")) {
                throw new IOException("Invalid or missing CSV header.");
            }

            String line;
            int lineNumber = 1;

            while ((line = reader.readLine()) != null) {
                lineNumber++;

                if (line.isBlank()) {
                    continue;
                }

                String[] fields = line.split(",", -1);

                if (fields.length != 5) {
                    System.err.println(
                            "Skipping line " + lineNumber +
                            ": expected 5 columns.");
                    continue;
                }

                try {
                    Instant timestamp = Instant.parse(fields[0].trim());

                    DnsQuery query = new DnsQuery(
                            timestamp,
                            fields[1].trim(),
                            fields[2].trim(),
                            fields[3].trim(),
                            fields[4].trim()
                    );

                    queries.add(query);

                } catch (DateTimeParseException |
                         IllegalArgumentException exception) {
                    System.err.println(
                            "Skipping line " + lineNumber +
                            ": " + exception.getMessage());
                }
            }
        }

        return queries;
    }
}
