package io.github.javatoailab.secureai.config;

import io.github.javatoailab.secureai.audit.AuditLog;
import io.github.javatoailab.secureai.audit.AuditSink;
import io.github.javatoailab.secureai.audit.ElasticsearchAuditSink;
import io.github.javatoailab.secureai.audit.JsonLinesAuditSink;
import io.github.javatoailab.secureai.injection.HeuristicInjectionDetector;
import io.github.javatoailab.secureai.injection.InjectionDetector;
import io.github.javatoailab.secureai.llm.UpstreamClient;
import io.github.javatoailab.secureai.pii.PiiDetector;
import io.github.javatoailab.secureai.pii.RegexPiiDetector;
import io.github.javatoailab.secureai.pii.Redactor;
import io.github.javatoailab.secureai.routing.Region;
import io.github.javatoailab.secureai.routing.ResidencyRouter;
import io.github.javatoailab.secureai.routing.Route;
import io.github.javatoailab.secureai.security.TenantRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.json.JsonMapper;

import java.time.Clock;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class SecureAiConfig {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    PiiDetector piiDetector() {
        return new RegexPiiDetector();
    }

    @Bean
    Redactor redactor(PiiDetector detector) {
        return new Redactor(detector);
    }

    @Bean
    InjectionDetector injectionDetector() {
        return new HeuristicInjectionDetector();
    }

    @Bean
    TenantRegistry tenantRegistry(SecureAiProperties props) {
        return new TenantRegistry(props.tenants() == null ? Map.of() : props.tenants());
    }

    @Bean
    ResidencyRouter residencyRouter(SecureAiProperties props) {
        Map<Region, Route> routes = new EnumMap<>(Region.class);
        if (props.routes() != null) {
            props.routes().forEach((region, r) -> routes.put(region, new Route(region, r.baseUrl(), r.model())));
        }
        return new ResidencyRouter(routes);
    }

    @Bean
    UpstreamClient upstreamClient(SecureAiProperties props, JsonMapper json) {
        Map<String, String> keys = new HashMap<>();
        if (props.routes() != null) {
            props.routes().values().stream()
                    .filter(r -> r.apiKey() != null)
                    .forEach(r -> keys.put(r.baseUrl().toString(), r.apiKey()));
        }
        SecureAiProperties.Upstream up = props.upstream();
        return up == null
                ? new UpstreamClient(java.time.Duration.ofSeconds(2), java.time.Duration.ofSeconds(60), keys, json)
                : new UpstreamClient(up.connectTimeout(), up.readTimeout(), keys, json);
    }

    @Bean
    AuditLog auditLog(SecureAiProperties props, JsonMapper json, Clock clock) {
        SecureAiProperties.Audit audit = props.audit();
        List<AuditSink> sinks = new ArrayList<>();
        int retained = 10_000;
        if (audit != null) {
            retained = audit.retained();
            if (audit.file() != null) {
                sinks.add(new JsonLinesAuditSink(audit.file(), json));
            }
            if (audit.elasticsearchUrl() != null && !audit.elasticsearchUrl().toString().isBlank()) {
                sinks.add(new ElasticsearchAuditSink(audit.elasticsearchUrl(), audit.elasticsearchIndex(), json));
            }
        }
        return new AuditLog(sinks, clock, retained);
    }
}
