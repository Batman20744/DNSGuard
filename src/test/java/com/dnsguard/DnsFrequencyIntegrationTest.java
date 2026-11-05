package com.dnsguard;

import com.dnsguard.detector.DnsDetector;
import com.dnsguard.model.DnsAlert;
import com.dnsguard.model.DnsQuery;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DnsFrequencyIntegrationTest {

    @Test
    void flagsRepeatedQueriesAfterConfiguredThreshold() {
        DnsDetector detector = new DnsDetector(
                253,                       // Long-domain threshold
                5.0,                       // Entropy threshold
                2,                         // Query threshold
                Duration.ofMinutes(1),
                100,                       // Unique subdomain threshold
                100,                       // Query-rate threshold
                100                        // TXT threshold
        );

        List<DnsAlert> alerts = List.of();

        for (int i = 0; i < 3; i++) {
            DnsQuery query = new DnsQuery(
                    Instant.parse("2026-10-24T10:00:0" + i + "Z"),
                    "192.168.1.50",
                    "mail.example.com",
                    "A",
                    "NOERROR"
            );

            alerts = detector.detect(query);

            if (i < 2) {
                assertTrue(alerts.isEmpty(),
                        "First two queries should not trigger an alert");
            }
        }

        assertEquals(1, alerts.size());

        DnsAlert alert = alerts.get(0);

        assertTrue(alert.getRuleIds().contains(
                DnsDetector.RULE_REPEATED_QUERY));

        assertTrue(alert.getReasons().stream().anyMatch(
                reason -> reason.contains("Repeated DNS queries")));

        assertEquals(30, alert.getRiskScore());
    }
}
