package com.dnsguard;

import com.dnsguard.detector.FrequencyTracker;
import com.dnsguard.model.DnsQuery;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class FrequencyTrackerTest {

    private DnsQuery createQuery(
            String sourceIp,
            String domain,
            String timestamp) {

        return new DnsQuery(
                Instant.parse(timestamp),
                sourceIp,
                domain,
                "A",
                "NOERROR"
        );
    }

    @Test
    void detectsRepeatedQueriesWithinThresholdWindow() {
        FrequencyTracker tracker =
                new FrequencyTracker(2, Duration.ofMinutes(1));

        assertFalse(tracker.recordAndCheck(createQuery(
                "192.168.1.10", "example.com",
                "2026-10-24T10:00:00Z")));

        assertFalse(tracker.recordAndCheck(createQuery(
                "192.168.1.10", "example.com",
                "2026-10-24T10:00:10Z")));

        assertTrue(tracker.recordAndCheck(createQuery(
                "192.168.1.10", "example.com",
                "2026-10-24T10:00:20Z")));
    }

    @Test
    void tracksDifferentDomainsSeparately() {
        FrequencyTracker tracker =
                new FrequencyTracker(1, Duration.ofMinutes(1));

        assertFalse(tracker.recordAndCheck(createQuery(
                "192.168.1.10", "example.com",
                "2026-10-24T10:00:00Z")));

        assertFalse(tracker.recordAndCheck(createQuery(
                "192.168.1.10", "another.com",
                "2026-10-24T10:00:05Z")));
    }

    @Test
    void rejectsInvalidQueryThreshold() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new FrequencyTracker(
                        0, Duration.ofMinutes(1))
        );
    }

    @Test
    void rejectsInvalidTimeWindow() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new FrequencyTracker(2, Duration.ZERO)
        );
    }

    @Test
    void ignoresQueriesOutsideTimeWindow() {
        FrequencyTracker tracker =
                new FrequencyTracker(2, Duration.ofMinutes(1));

        assertFalse(tracker.recordAndCheck(createQuery(
                "192.168.1.10", "example.com",
                "2026-10-24T10:00:00Z")));

        assertFalse(tracker.recordAndCheck(createQuery(
                "192.168.1.10", "example.com",
                "2026-10-24T10:00:30Z")));

        // The first query is outside the one-minute window.
        assertFalse(tracker.recordAndCheck(createQuery(
                "192.168.1.10", "example.com",
                "2026-10-24T10:01:01Z")));
    }

    @Test
    void tracksDifferentSourceIpsSeparately() {
        FrequencyTracker tracker =
                new FrequencyTracker(1, Duration.ofMinutes(1));

        assertFalse(tracker.recordAndCheck(createQuery(
                "192.168.1.10", "example.com",
                "2026-10-24T10:00:00Z")));

        assertFalse(tracker.recordAndCheck(createQuery(
                "192.168.1.11", "example.com",
                "2026-10-24T10:00:05Z")));
    }

    @Test
    void handlesOutOfOrderTimestamps() {
        FrequencyTracker tracker =
                new FrequencyTracker(2, Duration.ofMinutes(1));

        assertFalse(tracker.recordAndCheck(createQuery(
                "192.168.1.10", "example.com",
                "2026-10-24T10:00:20Z")));

        assertFalse(tracker.recordAndCheck(createQuery(
                "192.168.1.10", "example.com",
                "2026-10-24T10:00:00Z")));

        assertFalse(tracker.recordAndCheck(createQuery(
                "192.168.1.10", "example.com",
                "2026-10-24T10:00:10Z")));

        assertTrue(tracker.recordAndCheck(createQuery(
                "192.168.1.10", "example.com",
                "2026-10-24T10:00:30Z")));
    }
}
