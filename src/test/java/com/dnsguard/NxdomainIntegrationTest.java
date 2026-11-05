package com.dnsguard;

import com.dnsguard.detector.DnsDetector;
import com.dnsguard.model.DnsAlert;
import com.dnsguard.model.DnsQuery;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class NxdomainIntegrationTest {

    private DnsQuery query(
            String ip, String domain, String responseCode, int second) {
        return new DnsQuery(
                Instant.parse("2026-10-24T10:00:00Z")
                        .plusSeconds(second),
                ip,
                domain,
                "A",
                responseCode
        );
    }

    private DnsDetector createDetector() {
        return new DnsDetector(
                253,
                5.0,
                100,
                Duration.ofMinutes(1),
                100,
                100,
                100
        );
    }

    @Test
    void flagsSixthNxdomainResponseFromSameIp() {
        DnsDetector detector = createDetector();
        List<DnsAlert> alerts = List.of();

        for (int i = 0; i < 6; i++) {
            alerts = detector.detect(query(
                    "192.168.1.50",
                    "missing" + i + ".example.com",
                    "NXDOMAIN",
                    i
            ));

            if (i < 5) {
                assertTrue(alerts.isEmpty(),
                        "First five responses should not trigger an alert");
            }
        }

        assertEquals(1, alerts.size());

        DnsAlert alert = alerts.get(0);

        assertTrue(alert.getRuleIds().contains(
                DnsDetector.RULE_REPEATED_NXDOMAIN));

        assertTrue(alert.getReasons().stream().anyMatch(
                reason -> reason.contains("Repeated NXDOMAIN")));

        assertEquals(25, alert.getRiskScore());
    }

    @Test
    void successfulResponsesDoNotCountAsNxdomain() {
        DnsDetector detector = createDetector();

        for (int i = 0; i < 5; i++) {
            assertTrue(detector.detect(query(
                    "192.168.1.60",
                    "missing" + i + ".example.com",
                    "NOERROR",
                    i
            )).isEmpty());
        }

        assertTrue(detector.detect(query(
                "192.168.1.60",
                "missing-final.example.com",
                "NXDOMAIN",
                6
        )).isEmpty());
    }

    @Test
    void tracksDifferentSourceIpsSeparately() {
        DnsDetector detector = createDetector();

        for (int i = 0; i < 5; i++) {
            assertTrue(detector.detect(query(
                    "192.168.1.70",
                    "missing" + i + ".example.com",
                    "NXDOMAIN",
                    i
            )).isEmpty());

            assertTrue(detector.detect(query(
                    "192.168.1.71",
                    "missing" + i + ".example.com",
                    "NXDOMAIN",
                    i
            )).isEmpty());
        }
    }
}
