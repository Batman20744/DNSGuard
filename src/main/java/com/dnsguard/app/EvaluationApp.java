
package com.dnsguard.app;

import com.dnsguard.detector.DnsDetector;
import com.dnsguard.evaluation.DnsDatasetEvaluator;
import com.dnsguard.evaluation.DnsDatasetEvaluator.EvaluationResult;

import java.io.IOException;
import java.nio.file.Path;

public class EvaluationApp {

    public static void main(String[] args) {
        Path datasetPath = Path.of(
                args.length > 0
                        ? args[0]
                        : "data/labeled_dns_dataset.csv"
        );

        Path configPath = Path.of(
                args.length > 1
                        ? args[1]
                        : "config/dnsguard.properties"
        );

        try {
            DnsGuardConfig config = DnsGuardConfig.load(configPath);

            DnsDetector detector = new DnsDetector(
                    config.getDomainLengthThreshold(),
                    config.getEntropyThreshold(),
                    config.getRepeatedQueryThreshold(),
                    config.getTimeWindow(),
                    config.getUniqueSubdomainThreshold(),
                    config.getQueryRateThreshold(),
                    config.getTxtRepeatedQueryThreshold()
            );

            DnsDatasetEvaluator evaluator =
                    new DnsDatasetEvaluator();

            EvaluationResult result = evaluator.evaluate(
                    datasetPath,
                    detector,
                    config.getTimeWindow()
            );

            System.out.println();
            System.out.println("======================================");
            System.out.println("       DNSGuard v1.0.0");
            System.out.println("       DATASET EVALUATION");
            System.out.println("======================================");
            System.out.println(
                    "TXT repeated-query threshold: "
                            + config.getTxtRepeatedQueryThreshold());
            System.out.println(
                    "Detection time window: "
                            + config.getTimeWindow().toSeconds()
                            + " seconds");
            System.out.println();

            result.printReport();

        } catch (IOException | IllegalArgumentException e) {
            System.err.println(
                    "Evaluation failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
