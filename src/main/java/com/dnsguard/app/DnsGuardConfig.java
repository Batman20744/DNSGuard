package com.dnsguard.app;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Properties;

public class DnsGuardConfig {

    private static final int DEFAULT_TXT_REPEATED_THRESHOLD = 3;

    private final int domainLengthThreshold;
    private final double entropyThreshold;
    private final int repeatedQueryThreshold;
    private final Duration timeWindow;
    private final int uniqueSubdomainThreshold;
    private final int queryRateThreshold;
    private final int txtRepeatedQueryThreshold;

    public DnsGuardConfig(
            int domainLengthThreshold,
            double entropyThreshold,
            int repeatedQueryThreshold,
            Duration timeWindow,
            int uniqueSubdomainThreshold,
            int queryRateThreshold) {

        this(
                domainLengthThreshold,
                entropyThreshold,
                repeatedQueryThreshold,
                timeWindow,
                uniqueSubdomainThreshold,
                queryRateThreshold,
                DEFAULT_TXT_REPEATED_THRESHOLD
        );
    }

    public DnsGuardConfig(
            int domainLengthThreshold,
            double entropyThreshold,
            int repeatedQueryThreshold,
            Duration timeWindow,
            int uniqueSubdomainThreshold,
            int queryRateThreshold,
            int txtRepeatedQueryThreshold) {

        if (domainLengthThreshold < 1
                || domainLengthThreshold > 253) {
            throw new IllegalArgumentException(
                    "domain.length.threshold must be between 1 and 253");
        }

        if (!Double.isFinite(entropyThreshold)
                || entropyThreshold < 0.0
                || entropyThreshold > 5.0) {
            throw new IllegalArgumentException(
                    "entropy.threshold must be between 0 and 5");
        }

        if (repeatedQueryThreshold < 1) {
            throw new IllegalArgumentException(
                    "query.repeated.threshold must be at least 1");
        }

        if (timeWindow == null
                || timeWindow.isZero()
                || timeWindow.isNegative()) {
            throw new IllegalArgumentException(
                    "detection.window.seconds must be positive");
        }

        if (uniqueSubdomainThreshold < 1) {
            throw new IllegalArgumentException(
                    "subdomain.unique.threshold must be at least 1");
        }

        if (queryRateThreshold < 1) {
            throw new IllegalArgumentException(
                    "query.rate.threshold must be at least 1");
        }

        if (txtRepeatedQueryThreshold < 1) {
            throw new IllegalArgumentException(
                    "query.txt.repeated.threshold must be at least 1");
        }

        this.domainLengthThreshold = domainLengthThreshold;
        this.entropyThreshold = entropyThreshold;
        this.repeatedQueryThreshold = repeatedQueryThreshold;
        this.timeWindow = timeWindow;
        this.uniqueSubdomainThreshold = uniqueSubdomainThreshold;
        this.queryRateThreshold = queryRateThreshold;
        this.txtRepeatedQueryThreshold = txtRepeatedQueryThreshold;
    }

    public static DnsGuardConfig load(Path path) throws IOException {
        if (path == null
                || !Files.isRegularFile(path)
                || !Files.isReadable(path)) {
            throw new IOException(
                    "Configuration file does not exist or is not readable: "
                            + path);
        }

        Properties properties = new Properties();

        try (Reader reader = Files.newBufferedReader(
                path, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }

        int domainLength = readInt(
                properties, "domain.length.threshold");

        double entropy = readDouble(
                properties, "entropy.threshold");

        int repeatedThreshold = readInt(
                properties, "query.repeated.threshold");

        long windowSeconds = readLong(
                properties, "detection.window.seconds");

        int uniqueThreshold = readInt(
                properties, "subdomain.unique.threshold");

        int rateThreshold = readInt(
                properties, "query.rate.threshold");

        int txtThreshold = properties.containsKey(
                "query.txt.repeated.threshold")
                ? readInt(properties, "query.txt.repeated.threshold")
                : DEFAULT_TXT_REPEATED_THRESHOLD;

        Duration window;

        try {
            window = Duration.ofSeconds(windowSeconds);
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException(
                    "detection.window.seconds is too large", exception);
        }

        return new DnsGuardConfig(
                domainLength,
                entropy,
                repeatedThreshold,
                window,
                uniqueThreshold,
                rateThreshold,
                txtThreshold
        );
    }

    private static String required(
            Properties properties,
            String key) {

        String value = properties.getProperty(key);

        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    "Missing required configuration: " + key);
        }

        return value.trim();
    }

    private static int readInt(
            Properties properties,
            String key) {

        try {
            return Integer.parseInt(required(properties, key));
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(
                    "Configuration " + key
                            + " must be a valid integer", exception);
        }
    }

    private static long readLong(
            Properties properties,
            String key) {

        try {
            return Long.parseLong(required(properties, key));
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(
                    "Configuration " + key
                            + " must be a valid whole number", exception);
        }
    }

    private static double readDouble(
            Properties properties,
            String key) {

        try {
            return Double.parseDouble(required(properties, key));
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(
                    "Configuration " + key
                            + " must be a valid number", exception);
        }
    }

    public int getDomainLengthThreshold() {
        return domainLengthThreshold;
    }

    public double getEntropyThreshold() {
        return entropyThreshold;
    }

    public int getRepeatedQueryThreshold() {
        return repeatedQueryThreshold;
    }

    public Duration getTimeWindow() {
        return timeWindow;
    }

    public int getUniqueSubdomainThreshold() {
        return uniqueSubdomainThreshold;
    }

    public int getQueryRateThreshold() {
        return queryRateThreshold;
    }

    public int getTxtRepeatedQueryThreshold() {
        return txtRepeatedQueryThreshold;
    }
}
