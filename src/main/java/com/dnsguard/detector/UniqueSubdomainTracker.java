package com.dnsguard.detector;

import com.dnsguard.model.DnsQuery;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class UniqueSubdomainTracker {

    private final int subdomainThreshold;
    private final Duration timeWindow;

    private final Map<String, List<Entry>> history = new HashMap<>();

    public UniqueSubdomainTracker(
            int subdomainThreshold,
            Duration timeWindow) {

        if (subdomainThreshold < 1) {
            throw new IllegalArgumentException(
                    "Subdomain threshold must be at least 1");
        }

        if (timeWindow == null
                || timeWindow.isZero()
                || timeWindow.isNegative()) {
            throw new IllegalArgumentException(
                    "Time window must be positive");
        }

        this.subdomainThreshold = subdomainThreshold;
        this.timeWindow = timeWindow;
    }

    public synchronized boolean recordAndCheck(DnsQuery query) {
        if (query == null
                || query.getTimestamp() == null
                || query.getSourceIp() == null
                || query.getDomain() == null) {
            throw new IllegalArgumentException(
                    "Query, timestamp, source IP and domain "
                            + "must not be null");
        }

        String domain = query.getDomain()
                .toLowerCase(Locale.ROOT);

        // Ignore a trailing DNS root dot, if present.
        if (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }

        String[] labels = domain.split("\\.", -1);

        // A subdomain needs at least three labels:
        // host.example.com -> host + example + com.
        if (labels.length < 3) {
            return false;
        }

        for (String label : labels) {
            if (label.isEmpty()) {
                return false;
            }
        }

        String subdomain = labels[0];

        String parentDomain = domain.substring(
                domain.indexOf('.') + 1);

        String key = query.getSourceIp() + "|" + parentDomain;

        Instant currentTime = query.getTimestamp();
        Instant cutoff = currentTime.minus(timeWindow);

        List<Entry> entries = history.computeIfAbsent(
                key, ignored -> new ArrayList<>());

        // Remove entries outside this query's time window.
        entries.removeIf(entry ->
                entry.timestamp.isBefore(cutoff));

        // Insert by timestamp to support out-of-order logs.
        int insertionIndex = 0;

        while (insertionIndex < entries.size()
                && !entries.get(insertionIndex).timestamp
                        .isAfter(currentTime)) {
            insertionIndex++;
        }

        entries.add(insertionIndex,
                new Entry(currentTime, subdomain));

        // Count distinct labels observed in the window
        // up to the timestamp currently being processed.
        Set<String> uniqueSubdomains = new HashSet<>();

        for (Entry entry : entries) {
            if (!entry.timestamp.isBefore(cutoff)
                    && !entry.timestamp.isAfter(currentTime)) {
                uniqueSubdomains.add(entry.subdomain);
            }
        }

        return uniqueSubdomains.size() > subdomainThreshold;
    }

    private static class Entry {
        private final Instant timestamp;
        private final String subdomain;

        private Entry(Instant timestamp, String subdomain) {
            this.timestamp = timestamp;
            this.subdomain = subdomain;
        }
    }
}
