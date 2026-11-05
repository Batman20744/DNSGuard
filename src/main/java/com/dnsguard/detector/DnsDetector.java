package com.dnsguard.detector;

import com.dnsguard.model.DnsAlert;
import com.dnsguard.model.DnsQuery;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class DnsDetector {

    public static final String RULE_LONG_DOMAIN =
            "DNS_LONG_DOMAIN";
    public static final String RULE_HIGH_ENTROPY =
            "DNS_HIGH_ENTROPY";
    public static final String RULE_REPEATED_QUERY =
            "DNS_REPEATED_QUERY";
    public static final String RULE_UNIQUE_SUBDOMAINS =
            "DNS_UNIQUE_SUBDOMAINS";
    public static final String RULE_QUERY_BURST =
            "DNS_QUERY_BURST";
    public static final String RULE_REPEATED_TXT =
            "DNS_REPEATED_TXT";
    public static final String RULE_TXT_CORRELATION =
            "DNS_TXT_CORRELATION";
    public static final String RULE_REPEATED_NXDOMAIN =
            "DNS_REPEATED_NXDOMAIN";

    private static final int LONG_DOMAIN_POINTS = 50;
    private static final int HIGH_ENTROPY_POINTS = 30;
    private static final int REPEATED_QUERY_POINTS = 30;
    private static final int UNIQUE_SUBDOMAIN_POINTS = 30;
    private static final int QUERY_BURST_POINTS = 30;
    private static final int TXT_CORRELATION_POINTS = 20;
    private static final int REPEATED_TXT_QUERY_POINTS = 30;
    private static final int REPEATED_NXDOMAIN_POINTS = 25;

    private static final int MAX_RISK_SCORE = 100;

    private static final int DEFAULT_TXT_REPEATED_THRESHOLD = 3;
    private static final int DEFAULT_NXDOMAIN_THRESHOLD = 5;

    private final int domainLengthThreshold;
    private final double entropyThreshold;

    private final EntropyCalculator entropyCalculator;
    private final FrequencyTracker frequencyTracker;
    private final FrequencyTracker txtFrequencyTracker;
    private final UniqueSubdomainTracker uniqueSubdomainTracker;
    private final QueryRateTracker queryRateTracker;
    private final NxdomainTracker nxdomainTracker;

    public DnsDetector(int domainLengthThreshold) {
        this(
                domainLengthThreshold,
                3.5,
                10,
                Duration.ofMinutes(1),
                10,
                100,
                DEFAULT_TXT_REPEATED_THRESHOLD
        );
    }

    public DnsDetector(
            int domainLengthThreshold,
            double entropyThreshold,
            int queryThreshold,
            Duration timeWindow) {
        this(
                domainLengthThreshold,
                entropyThreshold,
                queryThreshold,
                timeWindow,
                10,
                100,
                DEFAULT_TXT_REPEATED_THRESHOLD
        );
    }

    public DnsDetector(
            int domainLengthThreshold,
            double entropyThreshold,
            int queryThreshold,
            Duration timeWindow,
            int uniqueSubdomainThreshold) {
        this(
                domainLengthThreshold,
                entropyThreshold,
                queryThreshold,
                timeWindow,
                uniqueSubdomainThreshold,
                100,
                DEFAULT_TXT_REPEATED_THRESHOLD
        );
    }

    public DnsDetector(
            int domainLengthThreshold,
            double entropyThreshold,
            int queryThreshold,
            Duration timeWindow,
            int uniqueSubdomainThreshold,
            int queryRateThreshold) {
        this(
                domainLengthThreshold,
                entropyThreshold,
                queryThreshold,
                timeWindow,
                uniqueSubdomainThreshold,
                queryRateThreshold,
                DEFAULT_TXT_REPEATED_THRESHOLD
        );
    }

    public DnsDetector(
            int domainLengthThreshold,
            double entropyThreshold,
            int queryThreshold,
            Duration timeWindow,
            int uniqueSubdomainThreshold,
            int queryRateThreshold,
            int txtRepeatedQueryThreshold) {

        if (domainLengthThreshold < 1
                || domainLengthThreshold > 253) {
            throw new IllegalArgumentException(
                    "Domain length threshold must be between 1 and 253");
        }

        if (!Double.isFinite(entropyThreshold)
                || entropyThreshold < 0.0
                || entropyThreshold > 5.0) {
            throw new IllegalArgumentException(
                    "Entropy threshold must be between 0 and 5");
        }

        if (txtRepeatedQueryThreshold < 1) {
            throw new IllegalArgumentException(
                    "TXT repeated-query threshold must be at least 1");
        }

        this.domainLengthThreshold = domainLengthThreshold;
        this.entropyThreshold = entropyThreshold;
        this.entropyCalculator = new EntropyCalculator();

        this.frequencyTracker =
                new FrequencyTracker(queryThreshold, timeWindow);

        this.txtFrequencyTracker =
                new FrequencyTracker(
                        txtRepeatedQueryThreshold, timeWindow);

        this.uniqueSubdomainTracker =
                new UniqueSubdomainTracker(
                        uniqueSubdomainThreshold, timeWindow);

        this.queryRateTracker =
                new QueryRateTracker(queryRateThreshold, timeWindow);

        this.nxdomainTracker =
                new NxdomainTracker(
                        DEFAULT_NXDOMAIN_THRESHOLD, timeWindow);
    }

    public List<DnsAlert> detect(DnsQuery query) {
        if (query == null || query.getDomain() == null) {
            throw new IllegalArgumentException(
                    "DNS query and domain must not be null");
        }

        List<String> reasons = new ArrayList<>();
        Set<String> ruleIds = new LinkedHashSet<>();
        int riskScore = 0;

        String domain = query.getDomain();

        // Rule 1: unusually long domains.
        if (domain.length() > domainLengthThreshold) {
            ruleIds.add(RULE_LONG_DOMAIN);
            reasons.add(
                    "Unusually long domain: "
                            + domain.length()
                            + " characters (+"
                            + LONG_DOMAIN_POINTS
                            + " risk points)");
            riskScore += LONG_DOMAIN_POINTS;
        }

        // Rule 2: high entropy in the first label.
        String firstLabel = domain.split("\\.", -1)[0];
        double entropy = entropyCalculator.calculate(firstLabel);

        if (entropy > entropyThreshold) {
            ruleIds.add(RULE_HIGH_ENTROPY);
            reasons.add(String.format(
                    Locale.ROOT,
                    "High-entropy first label: %.2f bits per character "
                            + "(+%d risk points)",
                    entropy,
                    HIGH_ENTROPY_POINTS));
            riskScore += HIGH_ENTROPY_POINTS;
        }

        // Rule 3: repeated queries to the same domain.
        if (frequencyTracker.recordAndCheck(query)) {
            ruleIds.add(RULE_REPEATED_QUERY);
            reasons.add(
                    "Repeated DNS queries from "
                            + query.getSourceIp()
                            + " to " + domain
                            + " within the configured time window (+"
                            + REPEATED_QUERY_POINTS
                            + " risk points)");
            riskScore += REPEATED_QUERY_POINTS;
        }

        // Rule 4: many unique subdomains under one parent.
        if (uniqueSubdomainTracker.recordAndCheck(query)) {
            ruleIds.add(RULE_UNIQUE_SUBDOMAINS);
            reasons.add(
                    "Unusually many unique subdomains queried by "
                            + query.getSourceIp()
                            + " under parent domain "
                            + getParentDomain(domain)
                            + " within the configured time window (+"
                            + UNIQUE_SUBDOMAIN_POINTS
                            + " risk points)");
            riskScore += UNIQUE_SUBDOMAIN_POINTS;
        }

        // Rule 5: high overall DNS query rate.
        if (queryRateTracker.recordAndCheck(query)) {
            ruleIds.add(RULE_QUERY_BURST);
            reasons.add(
                    "DNS query burst detected from source IP "
                            + query.getSourceIp()
                            + ": more than the configured query-rate "
                            + "threshold within the time window (+"
                            + QUERY_BURST_POINTS
                            + " risk points)");
            riskScore += QUERY_BURST_POINTS;
        }

        // Rule 6: repeated TXT queries.
        if ("TXT".equalsIgnoreCase(query.getRecordType())
                && txtFrequencyTracker.recordAndCheck(query)) {
            ruleIds.add(RULE_REPEATED_TXT);
            reasons.add(
                    "Repeated TXT queries from "
                            + query.getSourceIp()
                            + " to " + domain
                            + " exceeded the configured threshold "
                            + "within the time window (+"
                            + REPEATED_TXT_QUERY_POINTS
                            + " risk points)");
            riskScore += REPEATED_TXT_QUERY_POINTS;
        }

        // Rule 7: TXT queries correlated with another signal.
        if ("TXT".equalsIgnoreCase(query.getRecordType())
                && !reasons.isEmpty()) {
            ruleIds.add(RULE_TXT_CORRELATION);
            reasons.add(
                    "TXT record query combined with other suspicious "
                            + "signals (+"
                            + TXT_CORRELATION_POINTS
                            + " risk points)");
            riskScore += TXT_CORRELATION_POINTS;
        }

        // Rule 8: repeated NXDOMAIN responses from one source IP.
        if (nxdomainTracker.recordAndCheck(query)) {
            ruleIds.add(RULE_REPEATED_NXDOMAIN);
            reasons.add(
                    "Repeated NXDOMAIN responses from source IP "
                            + query.getSourceIp()
                            + " exceeded the configured threshold "
                            + "within the time window (+"
                            + REPEATED_NXDOMAIN_POINTS
                            + " risk points)");
            riskScore += REPEATED_NXDOMAIN_POINTS;
        }

        if (reasons.isEmpty()) {
            return List.of();
        }

        riskScore = Math.min(riskScore, MAX_RISK_SCORE);

        return List.of(new DnsAlert(
                query,
                riskScore,
                reasons,
                ruleIds
        ));
    }

    private String getParentDomain(String domain) {
        String normalized = domain.toLowerCase(Locale.ROOT);

        if (normalized.endsWith(".")) {
            normalized = normalized.substring(
                    0, normalized.length() - 1);
        }

        int firstDot = normalized.indexOf('.');

        return firstDot >= 0
                ? normalized.substring(firstDot + 1)
                : normalized;
    }
}
