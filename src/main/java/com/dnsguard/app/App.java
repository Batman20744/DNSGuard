package com.dnsguard.app;

import com.dnsguard.detector.DnsDetector;
import com.dnsguard.model.DnsAlert;
import com.dnsguard.model.DnsQuery;
import com.dnsguard.parser.DnsCsvParser;
import com.dnsguard.report.DnsCsvReportWriter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class App {

    public static void main(String[] args) {
        int exitCode = run(args);

        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    static int run(String[] args) {
        printHeader();

        try {
            Path inputFile = args.length >= 1
                    ? Path.of(args[0])
                    : Path.of("data", "dns_logs.csv");

            Path outputFile = args.length >= 2
                    ? Path.of(args[1])
                    : Path.of("reports", "dns_alerts.csv");

            Path configFile = args.length >= 3
                    ? Path.of(args[2])
                    : Path.of("config", "dnsguard.properties");

            if (!Files.isRegularFile(inputFile)
                    || !Files.isReadable(inputFile)) {
                System.err.println(
                        "ERROR: Input file does not exist or is not readable: "
                                + inputFile);
                printUsage();
                return 1;
            }

            DnsGuardConfig config = DnsGuardConfig.load(configFile);

            DnsCsvParser parser = new DnsCsvParser();

            // Connect all seven configurable detection parameters.
            DnsDetector detector = new DnsDetector(
                    config.getDomainLengthThreshold(),
                    config.getEntropyThreshold(),
                    config.getRepeatedQueryThreshold(),
                    config.getTimeWindow(),
                    config.getUniqueSubdomainThreshold(),
                    config.getQueryRateThreshold(),
                    config.getTxtRepeatedQueryThreshold()
            );

            DnsCsvReportWriter reportWriter =
                    new DnsCsvReportWriter();

            List<DnsQuery> queries = parser.parse(inputFile);
            List<DnsAlert> allAlerts = new ArrayList<>();

            System.out.println("Input file       : " + inputFile);
            System.out.println("Output report    : " + outputFile);
            System.out.println("Configuration    : " + configFile);
            System.out.println("Records loaded   : " + queries.size());
            System.out.println("Domain threshold : "
                    + config.getDomainLengthThreshold());
            System.out.println("Entropy threshold: "
                    + config.getEntropyThreshold());
            System.out.println("Repeated-query limit: "
                    + config.getRepeatedQueryThreshold());
            System.out.println("Unique subdomain limit: "
                    + config.getUniqueSubdomainThreshold());
            System.out.println("Query-rate limit : "
                    + config.getQueryRateThreshold());
            System.out.println("TXT-query limit  : "
                    + config.getTxtRepeatedQueryThreshold());
            System.out.println("Time window      : "
                    + config.getTimeWindow().toSeconds() + " seconds");

            printDivider();

            for (DnsQuery query : queries) {
                List<DnsAlert> alerts = detector.detect(query);

                for (DnsAlert alert : alerts) {
                    allAlerts.add(alert);
                    printAlert(alert);
                }
            }

            reportWriter.write(outputFile, allAlerts);

            printSummary(queries.size(), allAlerts);

            System.out.println();
            System.out.println("CSV report saved: " + outputFile);
            System.out.println("Alerts exported : " + allAlerts.size());

            return 0;

        } catch (InvalidPathException exception) {
            System.err.println(
                    "ERROR: Invalid file path: "
                            + exception.getMessage());
            return 1;

        } catch (IOException exception) {
            System.err.println(
                    "ERROR: File operation failed: "
                            + exception.getMessage());
            return 1;

        } catch (IllegalArgumentException exception) {
            System.err.println(
                    "ERROR: Invalid DNSGuard configuration or argument: "
                            + exception.getMessage());
            return 1;

        } catch (RuntimeException exception) {
            System.err.println(
                    "ERROR: DNSGuard could not complete the scan: "
                            + exception.getMessage());
            return 1;
        }
    }

    private static void printHeader() {
        System.out.println();
        System.out.println("==============================================");
        System.out.println("               DNSGuard v1.0.0");
        System.out.println("       DNS Exfiltration Detection System");
        System.out.println("==============================================");
        System.out.println(
                " Detection: Length | Entropy | Frequency | "
                        + "Unique Subdomains | Query Bursts | TXT");
        System.out.println();
    }

    private static void printAlert(DnsAlert alert) {
        DnsQuery query = alert.getQuery();

        System.out.println();
        System.out.println("+--------------------------------------------+");
        System.out.println("|              SECURITY ALERT                |");
        System.out.println("+--------------------------------------------+");
        System.out.println(" Severity    : " + alert.getSeverity());
        System.out.println(" Risk score  : " + alert.getRiskScore() + "/100");
        System.out.println(" Source IP   : " + query.getSourceIp());
        System.out.println(" Domain      : " + query.getDomain());
        System.out.println(" Record type : " + query.getRecordType());
        System.out.println(" Response    : " + query.getResponseCode());
        System.out.println(" Timestamp   : " + query.getTimestamp());
        System.out.println(" Reasons:");

        for (String reason : alert.getReasons()) {
            System.out.println("   - " + reason);
        }

        System.out.println("+--------------------------------------------+");
    }

    private static void printSummary(
            int recordsAnalyzed,
            List<DnsAlert> alerts) {

        long high = alerts.stream()
                .filter(a -> a.getSeverity() == DnsAlert.Severity.HIGH)
                .count();

        long medium = alerts.stream()
                .filter(a -> a.getSeverity() == DnsAlert.Severity.MEDIUM)
                .count();

        long low = alerts.stream()
                .filter(a -> a.getSeverity() == DnsAlert.Severity.LOW)
                .count();

        System.out.println();
        System.out.println("==============================================");
        System.out.println("                 SCAN SUMMARY");
        System.out.println("==============================================");
        System.out.println(" DNS records analyzed : " + recordsAnalyzed);
        System.out.println(" Total alerts         : " + alerts.size());
        System.out.println(" HIGH severity        : " + high);
        System.out.println(" MEDIUM severity      : " + medium);
        System.out.println(" LOW severity         : " + low);
        System.out.println("==============================================");
        System.out.println("DNSGuard analysis completed.");
        System.out.println(
                "Alerts are indicators, not proof of an attack.");
    }

    private static void printDivider() {
        System.out.println("----------------------------------------------");
    }

    private static void printUsage() {
        System.err.println(
                "Usage: App [input.csv] [output.csv] [config.properties]");
    }
}
