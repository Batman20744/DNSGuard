package com.dnsguard;

import com.dnsguard.app.DnsGuardConfig;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class DnsGuardConfigTest {

    @TempDir
    Path tempDir;

    @Test
    void loadsValidConfiguration() throws IOException {
        Path configFile = tempDir.resolve("valid.properties");

        Files.writeString(
                configFile,
                """
                domain.length.threshold=40
                entropy.threshold=3.2
                query.repeated.threshold=8
                detection.window.seconds=120
                subdomain.unique.threshold=12
                query.rate.threshold=90
                """,
                StandardCharsets.UTF_8
        );

        DnsGuardConfig config = DnsGuardConfig.load(configFile);

        assertEquals(40, config.getDomainLengthThreshold());
        assertEquals(3.2, config.getEntropyThreshold(), 0.0001);
        assertEquals(8, config.getRepeatedQueryThreshold());
        assertEquals(Duration.ofSeconds(120), config.getTimeWindow());
        assertEquals(12, config.getUniqueSubdomainThreshold());
        assertEquals(90, config.getQueryRateThreshold());
    }

    @Test
    void rejectsMissingConfigurationFile() {
        Path missingFile = tempDir.resolve("missing.properties");

        assertThrows(
                IOException.class,
                () -> DnsGuardConfig.load(missingFile)
        );
    }

    @Test
    void rejectsInvalidDomainLengthThreshold() throws IOException {
        Path configFile = tempDir.resolve("invalid.properties");

        Files.writeString(
                configFile,
                """
                domain.length.threshold=0
                entropy.threshold=3.5
                query.repeated.threshold=10
                detection.window.seconds=60
                subdomain.unique.threshold=10
                query.rate.threshold=100
                """,
                StandardCharsets.UTF_8
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsGuardConfig.load(configFile)
        );
    }

    @Test
    void rejectsMissingRequiredSetting() throws IOException {
        Path configFile = tempDir.resolve("incomplete.properties");

        Files.writeString(
                configFile,
                """
                domain.length.threshold=30
                entropy.threshold=3.5
                query.repeated.threshold=10
                detection.window.seconds=60
                subdomain.unique.threshold=10
                """,
                StandardCharsets.UTF_8
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsGuardConfig.load(configFile)
        );
    }
}
