package io.github.javatoailab.secureai.security;

import io.github.javatoailab.secureai.audit.AuditLog;
import io.github.javatoailab.secureai.injection.InjectionDetector;
import io.github.javatoailab.secureai.pii.Redactor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import tools.jackson.databind.json.JsonMapper;

/**
 * The whole policy in one place. The two custom filters are created here rather than declared as
 * beans, so Spring Boot does not also register them as plain servlet filters and run them twice.
 *
 * <pre>
 *   ApiKeyAuthenticationFilter  → who is calling, and which policy applies
 *   AuthorizationFilter         → may they call this endpoint at all
 *   PromptInspectionFilter      → injection check, PII block or redact, audit refusals
 *   ChatController              → residency routing, upstream call, response scan, audit
 * </pre>
 */
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, TenantRegistry tenants, JsonMapper json,
                                    InjectionDetector injection, Redactor redactor, AuditLog audit) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .httpBasic(b -> b.disable())
                .formLogin(f -> f.disable())
                .logout(l -> l.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((req, res, ex) ->
                                ErrorResponses.write(res, 401, "unauthenticated", "API key required", null))
                        .accessDeniedHandler((req, res, ex) ->
                                ErrorResponses.write(res, 403, "forbidden", "Not allowed for this tenant", null)))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/actuator/health/**", "/actuator/health").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/v1/**").hasRole("TENANT")
                        .anyRequest().denyAll())
                .addFilterBefore(new ApiKeyAuthenticationFilter(tenants), AnonymousAuthenticationFilter.class)
                .addFilterAfter(new PromptInspectionFilter(json, injection, redactor, audit), AuthorizationFilter.class);
        return http.build();
    }
}
