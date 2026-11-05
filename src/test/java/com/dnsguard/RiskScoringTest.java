package com.dnsguard;

import com.dnsguard.detector.DnsDetector;
import com.dnsguard.model.DnsAlert;
import com.dnsguard.model.DnsQuery;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RiskScoringTest {

    @Test
    void longDomainContributesFiftyRiskPoints() {
        DnsDetector detector = new DnsDetector(20);

        DnsQuery query = new DnsQuery(
                Instant.parse("2026-10-24T14:00:00Z"),
                "192.168.1.70",
                "normalname.example.com",
                "A",
                "NOERROR"
        );

        List<DnsAlert> alerts = detector.detect(query);

        assertEquals(1, alerts.size());
        assertEquals(50, alerts.get(0).getRiskScore());
        assertEquals(DnsAlert.Severity.MEDIUM,
                alerts.get(0).getSeverity());

        assertTrue(alerts.get(0).getReasons().stream()
                .anyMatch(reason ->
                        reason.contains("+50 risk points")));
    }

    @Test
    void riskScoreNeverExceedsOneHundred() {
        DnsDetector detector = new DnsDetector(10);

        DnsQuery query = new DnsQuery(
                Instant.parse("2026-10-24T14:01:00Z"),
                "192.168.1.71",
                "abcdefghijklmnopqrstuvwxyz1234567890.example.com",
                "TXT",
                "NOERROR"
        );

        List<DnsAlert> alerts = detector.detect(query);

        assertEquals(1, alerts.size());
        assertEquals(100, alerts.get(0).getRiskScore());
        assertEquals(DnsAlert.Severity.HIGH,
                alerts.get(0).getSeverity());
    }

    @Test
    void severityMatchesRiskScoreBoundaries() {
        DnsQuery query = new DnsQuery(
                Instant.parse("2026-10-24T14:02:00Z"),
                "192.168.1.72",
                "example.com",
                "A",
                "NOERROR"
        );

        assertEquals(
                DnsAlert.Severity.LOW,
                new DnsAlert(query, 39, List.of("Test")).getSeverity()
        );

        assertEquals(
                DnsAlert.Severity.MEDIUM,
                new DnsAlert(query, 40, List.of("Test")).getSeverity()
        );

        assertEquals(
                DnsAlert.Severity.MEDIUM,
                new DnsAlert(query, 69, List.of("Test")).getSeverity()
        );

        assertEquals(
                DnsAlert.Severity.HIGH,
                new DnsAlert(query, 70, List.of("Test")).getSeverity()
        );
    }

    @Test
    void rejectsRiskScoresOutsideValidRange() {
        DnsQuery query = new DnsQuery(
                Instant.parse("2026-10-24T14:03:00Z"),
                "192.168.1.73",
                "example.com",
                "A",
                "NOERROR"
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsAlert(query, -1, List.of("Test"))
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsAlert(query, 101, List.of("Test"))
        );
    }
}
