package com.dnsguard;

import com.dnsguard.detector.DnsDetector;
import com.dnsguard.detector.EntropyCalculator;
import com.dnsguard.model.DnsAlert;
import com.dnsguard.model.DnsQuery;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

class DnsDetectorTest {

    @Test
    void flagsLongHighEntropyDomain() {
        DnsDetector detector = new DnsDetector(30);

        DnsQuery query = new DnsQuery(
                Instant.parse("2026-10-24T10:00:00Z"),
                "192.168.1.14",
                "abcdefghijklmnopqrstuvwxyz1234567890.example.com",
                "TXT",
                "NOERROR"
        );

        List<DnsAlert> alerts = detector.detect(query);

        assertEquals(1, alerts.size());

        DnsAlert alert = alerts.get(0);

        assertEquals(100, alert.getRiskScore());
        assertEquals(DnsAlert.Severity.HIGH, alert.getSeverity());
        assertEquals(3, alert.getReasons().size());

        assertTrue(alert.getReasons().stream()
                .anyMatch(reason ->
                        reason.contains("Unusually long domain")));

        assertTrue(alert.getReasons().stream()
                .anyMatch(reason ->
                        reason.contains("High-entropy")));

        assertTrue(alert.getReasons().stream()
                .anyMatch(reason ->
                        reason.contains("TXT record query")));
    }

    @Test
    void doesNotFlagShortLowEntropyDomain() {
        DnsDetector detector = new DnsDetector(30);

        DnsQuery query = new DnsQuery(
                Instant.parse("2026-10-24T10:00:00Z"),
                "192.168.1.10",
                "mail.example.com",
                "A",
                "NOERROR"
        );

        assertTrue(detector.detect(query).isEmpty());
    }

    @Test
    void rejectsInvalidThreshold() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsDetector(0)
        );
    }

    @Test
    void calculatesZeroEntropyForRepeatedCharacters() {
        EntropyCalculator calculator = new EntropyCalculator();

        assertEquals(
                0.0,
                calculator.calculate("aaaa"),
                0.0001
        );
    }

    @Test
    void calculatesPositiveEntropyForVariedCharacters() {
        EntropyCalculator calculator = new EntropyCalculator();

        assertTrue(
                calculator.calculate("a8x9q2m7z5") > 3.0
        );
    }

    @Test
    void detectsRepeatedQueriesThroughMainDetector() {
        DnsDetector detector = new DnsDetector(
                253,
                5.0,
                2,
                Duration.ofMinutes(1)
        );

        List<DnsAlert> alerts = new ArrayList<>();

        for (int i = 0; i < 3; i++) {
            String timestamp = String.format(
                    Locale.ROOT,
                    "2026-10-24T10:00:%02dZ",
                    i * 10
            );

            DnsQuery query = new DnsQuery(
                    Instant.parse(timestamp),
                    "192.168.1.20",
                    "example.com",
                    "A",
                    "NOERROR"
            );

            alerts = detector.detect(query);
        }

        assertEquals(1, alerts.size());

        DnsAlert alert = alerts.get(0);

        assertTrue(alert.getRiskScore() >= 30);

        assertTrue(alert.getReasons().stream()
                .anyMatch(reason ->
                        reason.contains("Repeated DNS queries")));
    }

    @Test
    void doesNotFlagNormalTxtQueryByRecordTypeAlone() {
        DnsDetector detector = new DnsDetector(30);

        DnsQuery query = new DnsQuery(
                Instant.parse("2026-10-24T11:00:00Z"),
                "192.168.1.30",
                "example.com",
                "TXT",
                "NOERROR"
        );

        assertTrue(detector.detect(query).isEmpty());
    }

    @Test
    void doesNotFlagTxtNxDomainResponseByItself() {
        DnsDetector detector = new DnsDetector(30);

        DnsQuery query = new DnsQuery(
                Instant.parse("2026-10-24T14:01:20Z"),
                "192.168.1.24",
                "transfer.example.net",
                "TXT",
                "NXDOMAIN"
        );

        assertTrue(detector.detect(query).isEmpty());
    }

    @Test
    void detectsManyUniqueSubdomains() {
        DnsDetector detector = new DnsDetector(
                253,
                5.0,
                100,
                Duration.ofMinutes(1),
                2
        );

        List<DnsAlert> alerts = List.of();

        String[] domains = {
                "a1.example.com",
                "b2.example.com",
                "c3.example.com"
        };

        for (int i = 0; i < domains.length; i++) {
            DnsQuery query = new DnsQuery(
                    Instant.parse(String.format(
                            Locale.ROOT,
                            "2026-10-24T10:00:%02dZ",
                            i * 10
                    )),
                    "192.168.1.40",
                    domains[i],
                    "A",
                    "NOERROR"
            );

            alerts = detector.detect(query);
        }

        assertEquals(1, alerts.size());

        assertTrue(alerts.get(0).getReasons().stream()
                .anyMatch(reason ->
                        reason.contains("unique subdomains")));
    }

    @Test
    void repeatedSameSubdomainDoesNotTriggerUniqueSubdomainRule() {
        DnsDetector detector = new DnsDetector(
                253,
                5.0,
                100,
                Duration.ofMinutes(1),
                2
        );

        for (int i = 0; i < 3; i++) {
            DnsQuery query = new DnsQuery(
                    Instant.parse(String.format(
                            Locale.ROOT,
                            "2026-10-24T11:00:%02dZ",
                            i * 10
                    )),
                    "192.168.1.41",
                    "same.example.com",
                    "A",
                    "NOERROR"
            );

            assertTrue(detector.detect(query).isEmpty());
        }
    }

    @Test
    void detectsDnsQueryBurstAcrossDifferentDomains() {
        DnsDetector detector = new DnsDetector(
                253,
                5.0,
                100,
                Duration.ofSeconds(10),
                100,
                5
        );

        List<DnsAlert> alerts = List.of();

        for (int i = 0; i < 6; i++) {
            DnsQuery query = new DnsQuery(
                    Instant.parse(String.format(
                            Locale.ROOT,
                            "2026-10-24T12:00:%02dZ",
                            i
                    )),
                    "192.168.1.50",
                    "host" + i + ".example.com",
                    "A",
                    "NOERROR"
            );

            alerts = detector.detect(query);
        }

        assertEquals(1, alerts.size());

        assertTrue(alerts.get(0).getReasons().stream()
                .anyMatch(reason ->
                        reason.contains("DNS query burst detected")));
    }

    @Test
    void doesNotFlagDnsTrafficBelowBurstThreshold() {
        DnsDetector detector = new DnsDetector(
                253,
                5.0,
                100,
                Duration.ofSeconds(10),
                100,
                5
        );

        for (int i = 0; i < 5; i++) {
            DnsQuery query = new DnsQuery(
                    Instant.parse(String.format(
                            Locale.ROOT,
                            "2026-10-24T13:00:%02dZ",
                            i
                    )),
                    "192.168.1.60",
                    "host" + i + ".example.com",
                    "A",
                    "NOERROR"
            );

            assertTrue(detector.detect(query).isEmpty());
        }
    }

    // New TXT detection tests

    private DnsDetector createTxtTestDetector() {
        return new DnsDetector(
                253,                    // Domain length threshold
                5.0,                    // Entropy threshold
                100,                    // Normal repeated-query threshold
                Duration.ofMinutes(1),  // Detection time window
                100,                    // Unique subdomain threshold
                100,                    // Query-rate threshold
                2                       // TXT repeated-query threshold
        );
    }

    private DnsQuery createTxtQuery(int seconds) {
        return new DnsQuery(
                Instant.parse(String.format(
                        Locale.ROOT,
                        "2026-10-24T15:00:%02dZ",
                        seconds
                )),
                "192.168.1.70",
                "transfer.example.com",
                "TXT",
                "NOERROR"
        );
    }

    @Test
    void doesNotFlagSingleTxtQueryWithNewRule() {
        DnsDetector detector = createTxtTestDetector();

        List<DnsAlert> alerts =
                detector.detect(createTxtQuery(0));

        assertTrue(alerts.isEmpty());
    }

    @Test
    void doesNotFlagTwoTxtQueriesWhenThresholdIsTwo() {
        DnsDetector detector = createTxtTestDetector();

        for (int i = 0; i < 2; i++) {
            List<DnsAlert> alerts =
                    detector.detect(createTxtQuery(i * 10));

            assertTrue(
                    alerts.stream().noneMatch(alert ->
                            alert.getReasons().stream().anyMatch(reason ->
                                    reason.contains("Repeated TXT queries"))),
                    "The repeated-TXT rule should not trigger "
                            + "until the threshold is exceeded"
            );
        }
    }

    @Test
    void flagsThirdTxtQueryWhenThresholdIsTwo() {
        DnsDetector detector = createTxtTestDetector();

        for (int i = 0; i < 2; i++) {
            detector.detect(createTxtQuery(i * 10));
        }

        List<DnsAlert> alerts =
                detector.detect(createTxtQuery(20));

        assertEquals(1, alerts.size());

        DnsAlert alert = alerts.get(0);

        assertTrue(alert.getRiskScore() >= 30);

        assertTrue(alert.getReasons().stream()
                .anyMatch(reason ->
                        reason.contains("Repeated TXT queries")));
    }

    @Test
    void repeatedTxtAlertExplainsDetectionReason() {
        DnsDetector detector = createTxtTestDetector();

        for (int i = 0; i < 2; i++) {
            detector.detect(createTxtQuery(i * 10));
        }

        List<DnsAlert> alerts =
                detector.detect(createTxtQuery(20));

        assertEquals(1, alerts.size());

        String txtReason = alerts.get(0).getReasons().stream()
                .filter(reason ->
                        reason.contains("Repeated TXT queries"))
                .findFirst()
                .orElseThrow(() ->
                        new AssertionError(
                                "Expected an explanation for repeated TXT queries"
                        ));

        assertTrue(txtReason.contains("192.168.1.70"));
        assertTrue(txtReason.contains("transfer.example.com"));
        assertTrue(txtReason.contains("30 risk points"));
    }
}
