package com.dnsguard.detector;

import com.dnsguard.model.DnsQuery;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class QueryRateTracker {

    private final int queryThreshold;
    private final Duration timeWindow;

    private final Map<String, List<Instant>> history = new HashMap<>();

    public QueryRateTracker(int queryThreshold, Duration timeWindow) {
        if (queryThreshold < 1) {
            throw new IllegalArgumentException(
                    "Query-rate threshold must be at least 1");
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
                || query.getSourceIp().isBlank()) {
            throw new IllegalArgumentException(
                    "Query, timestamp and source IP must be valid");
        }

        String sourceIp = query.getSourceIp();
        Instant currentTime = query.getTimestamp();
        Instant cutoff = currentTime.minus(timeWindow);

        List<Instant> timestamps = history.computeIfAbsent(
                sourceIp, ignored -> new ArrayList<>());

        // Remove timestamps older than the current rolling window.
        timestamps.removeIf(timestamp -> timestamp.isBefore(cutoff));

        // Insert in timestamp order to support out-of-order log entries.
        int index = 0;

        while (index < timestamps.size()
                && !timestamps.get(index).isAfter(currentTime)) {
            index++;
        }

        timestamps.add(index, currentTime);

        // Count queries in the window ending at currentTime.
        int count = 0;

        for (Instant timestamp : timestamps) {
            if (!timestamp.isBefore(cutoff)
                    && !timestamp.isAfter(currentTime)) {
                count++;
            }
        }

        return count > queryThreshold;
    }
}
