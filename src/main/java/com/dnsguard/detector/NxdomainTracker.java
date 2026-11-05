package com.dnsguard.detector;

import com.dnsguard.model.DnsQuery;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class NxdomainTracker {

    private final int queryThreshold;
    private final Duration timeWindow;

    private final Map<String, List<Instant>> responseTimes =
            new HashMap<>();

    public NxdomainTracker(
            int queryThreshold,
            Duration timeWindow) {

        if (queryThreshold < 1) {
            throw new IllegalArgumentException(
                    "NXDOMAIN threshold must be at least 1");
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

        if (query == null || query.getTimestamp() == null
                || query.getSourceIp() == null
                || query.getResponseCode() == null) {
            throw new IllegalArgumentException(
                    "Query, timestamp, source IP and response code "
                            + "must not be null");
        }

        if (!"NXDOMAIN".equalsIgnoreCase(query.getResponseCode())) {
            return false;
        }

        String sourceIp = query.getSourceIp();
        Instant currentTime = query.getTimestamp();
        Instant cutoff = currentTime.minus(timeWindow);

        List<Instant> timestamps =
                responseTimes.computeIfAbsent(
                        sourceIp, ignored -> new ArrayList<>());

        int insertionIndex = java.util.Collections.binarySearch(
                timestamps, currentTime);

        if (insertionIndex < 0) {
            insertionIndex = -insertionIndex - 1;
        }

        timestamps.add(insertionIndex, currentTime);

        timestamps.removeIf(
                timestamp -> timestamp.isBefore(cutoff));

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
