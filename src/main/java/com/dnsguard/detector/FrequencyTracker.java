package com.dnsguard.detector;

import com.dnsguard.model.DnsQuery;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class FrequencyTracker {

    private final int queryThreshold;
    private final Duration timeWindow;

    private final Map<String, List<Instant>> queryTimes =
            new HashMap<>();

    public FrequencyTracker(
            int queryThreshold,
            Duration timeWindow) {

        if (queryThreshold < 1) {
            throw new IllegalArgumentException(
                    "Query threshold must be at least 1");
        }

        if (timeWindow == null
                || timeWindow.isZero()
                || timeWindow.isNegative()) {
            throw new IllegalArgumentException(
                    "Time window must be positive");
        }

        this.queryThreshold = queryThreshold;
        this.timeWindow = timeWindow;
    }

    public synchronized boolean recordAndCheck(DnsQuery query) {
        if (query == null
                || query.getTimestamp() == null
                || query.getSourceIp() == null
                || query.getDomain() == null) {
            throw new IllegalArgumentException(
                    "DNS query, timestamp, source IP and domain "
                            + "must not be null");
        }

        String key = query.getSourceIp() + "|"
                + query.getDomain().toLowerCase(Locale.ROOT);

        Instant currentTime = query.getTimestamp();
        Instant cutoff = currentTime.minus(timeWindow);

        List<Instant> timestamps =
                queryTimes.computeIfAbsent(
                        key, ignored -> new ArrayList<>());

        // Keep timestamps sorted, even when logs arrive out of order.
        int insertionIndex = java.util.Collections.binarySearch(
                timestamps, currentTime);

        if (insertionIndex < 0) {
            insertionIndex = -insertionIndex - 1;
        }

        timestamps.add(insertionIndex, currentTime);

        // Remove timestamps that are older than this query's window.
        timestamps.removeIf(timestamp ->
                timestamp.isBefore(cutoff));

        // Count only timestamps within the window and not later
        // than the timestamp of the query currently being checked.
        int countInWindow = 0;

        for (Instant timestamp : timestamps) {
            if (!timestamp.isBefore(cutoff)
                    && !timestamp.isAfter(currentTime)) {
                countInWindow++;
            }
        }

        return countInWindow > queryThreshold;
    }
}
