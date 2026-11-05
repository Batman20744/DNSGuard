package com.dnsguard.evaluation;

public final class RulePerformanceStats {

    private final String ruleId;
    private int suspiciousTriggers;
    private int normalTriggers;

    public RulePerformanceStats(String ruleId) {
        if (ruleId == null || ruleId.isBlank()) {
            throw new IllegalArgumentException(
                    "Rule ID must not be blank");
        }

        this.ruleId = ruleId;
    }

    public void recordTrigger(boolean actuallySuspicious) {
        if (actuallySuspicious) {
            suspiciousTriggers++;
        } else {
            normalTriggers++;
        }
    }

    public String getRuleId() {
        return ruleId;
    }

    public int getSuspiciousTriggers() {
        return suspiciousTriggers;
    }

    public int getNormalTriggers() {
        return normalTriggers;
    }

    public int getTotalTriggers() {
        return suspiciousTriggers + normalTriggers;
    }

    public double getSuspiciousTriggerRate() {
        int total = getTotalTriggers();

        return total == 0
                ? 0.0
                : (double) suspiciousTriggers / total;
    }

    @Override
    public String toString() {
        return ruleId
                + " | Total triggers: " + getTotalTriggers()
                + " | Suspicious records: " + suspiciousTriggers
                + " | Normal records: " + normalTriggers;
    }
}
