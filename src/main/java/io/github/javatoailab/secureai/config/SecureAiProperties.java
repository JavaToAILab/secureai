package io.github.javatoailab.secureai.config;

import io.github.javatoailab.secureai.routing.Region;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

@ConfigurationProperties("secureai")
public record SecureAiProperties(
        Map<String, Tenant> tenants,
        Map<Region, RouteProps> routes,
        Audit audit,
        Upstream upstream) {

    /**
     * A calling application. Only the SHA-256 of its API key is configured, so a leaked config file
     * does not leak working credentials.
     */
    public record Tenant(
            String apiKeySha256,
            Region region,
            @DefaultValue("REDACT") PiiAction piiAction,
            @DefaultValue("0.5") double injectionThreshold,
            @DefaultValue("false") boolean admin) {
    }

    public record RouteProps(URI baseUrl, String model, String apiKey) {
    }

    public record Audit(
            @DefaultValue("audit/audit.jsonl") Path file,
            URI elasticsearchUrl,
            @DefaultValue("secureai-audit") String elasticsearchIndex,
            @DefaultValue("10000") int retained) {
    }

    public record Upstream(
            @DefaultValue("2s") Duration connectTimeout,
            @DefaultValue("60s") Duration readTimeout) {
    }
}
