
package com.dnsguard.model;

import java.time.Instant;
import java.util.Objects;

public class DnsQuery {

    private final Instant timestamp;
    private final String sourceIp;
    private final String domain;
    private final String recordType;
    private final String responseCode;

    public DnsQuery(
            Instant timestamp,
            String sourceIp,
            String domain,
            String recordType,
            String responseCode) {

        this.timestamp = Objects.requireNonNull(
                timestamp, "Timestamp cannot be null");

        this.sourceIp = requireText(sourceIp, "Source IP");
        this.domain = requireText(domain, "Domain");
        this.recordType = requireText(recordType, "Record type")
                .toUpperCase();
        this.responseCode = requireText(responseCode, "Response code")
                .toUpperCase();
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    fieldName + " cannot be empty");
        }

        return value.trim();
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getDomain() {
        return domain;
    }

    public String getRecordType() {
        return recordType;
    }

    public String getResponseCode() {
        return responseCode;
    }

    @Override
    public String toString() {
        return "DnsQuery{" +
                "timestamp=" + timestamp +
                ", sourceIp='" + sourceIp + '\'' +
                ", domain='" + domain + '\'' +
                ", recordType='" + recordType + '\'' +
                ", responseCode='" + responseCode + '\'' +
                '}';
    }
}
