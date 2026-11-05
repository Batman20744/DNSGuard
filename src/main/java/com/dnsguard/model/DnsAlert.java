package com.dnsguard.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class DnsAlert {

    public enum Severity {
        LOW,
        MEDIUM,
        HIGH
    }

    private static final int MEDIUM_THRESHOLD = 40;
    private static final int HIGH_THRESHOLD = 70;

    private final DnsQuery query;
    private final int riskScore;
    private final Severity severity;
    private final List<String> reasons;
    private final Set<String> ruleIds;

    /**
     * Backward-compatible constructor.
     */
    public DnsAlert(
            DnsQuery query,
            int riskScore,
            List<String> reasons) {
        this(query, riskScore, reasons, Collections.emptySet());
    }

    /**
     * Creates an alert with stable detection-rule identifiers.
     */
    public DnsAlert(
            DnsQuery query,
            int riskScore,
            List<String> reasons,
            Set<String> ruleIds) {

        this.query = Objects.requireNonNull(
                query, "Query cannot be null");

        if (riskScore < 0 || riskScore > 100) {
            throw new IllegalArgumentException(
                    "Risk score must be between 0 and 100");
        }

        this.riskScore = riskScore;
        this.severity = calculateSeverity(riskScore);

        Objects.requireNonNull(reasons, "Reasons cannot be null");
        this.reasons = List.copyOf(reasons);

        Objects.requireNonNull(ruleIds, "Rule IDs cannot be null");
        this.ruleIds = Collections.unmodifiableSet(
                new LinkedHashSet<>(ruleIds));
    }

    private Severity calculateSeverity(int score) {
        if (score >= HIGH_THRESHOLD) {
            return Severity.HIGH;
        }

        if (score >= MEDIUM_THRESHOLD) {
            return Severity.MEDIUM;
        }

        return Severity.LOW;
    }

    public DnsQuery getQuery() {
        return query;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public Severity getSeverity() {
        return severity;
    }

    public List<String> getReasons() {
        return reasons;
    }

    public Set<String> getRuleIds() {
        return ruleIds;
    }

    /**
     * Human-readable severity guidance for analyst triage.
     */
    public String getSeverityDescription() {
        return switch (severity) {
            case HIGH ->
                    "High priority: investigate promptly.";
            case MEDIUM ->
                    "Medium priority: review the evidence.";
            case LOW ->
                    "Low priority: monitor and gather context.";
        };
    }

    @Override
    public String toString() {
        return "DnsAlert{" +
                "domain='" + query.getDomain() + '\'' +
                ", riskScore=" + riskScore +
                ", severity=" + severity +
                ", severityDescription='" + getSeverityDescription() + '\'' +
                ", ruleIds=" + ruleIds +
                ", reasons=" + reasons +
                '}';
    }
}
