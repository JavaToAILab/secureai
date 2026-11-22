package io.github.javatoailab.secureai.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * Accepts {@code Authorization: Bearer <key>} (what OpenAI SDKs send) or {@code X-API-Key}. A key
 * that is present but unknown gets a 401 here; a missing key falls through and is rejected by the
 * authorization rules.
 */
public final class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    private final TenantRegistry tenants;

    public ApiKeyAuthenticationFilter(TenantRegistry tenants) {
        this.tenants = tenants;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Optional<String> key = extractKey(request);
        if (key.isPresent()) {
            Optional<TenantPrincipal> tenant = tenants.authenticate(key.get());
            if (tenant.isEmpty()) {
                ErrorResponses.write(response, 401, "invalid_api_key", "API key not recognised", null);
                return;
            }
            SecurityContextHolder.getContext().setAuthentication(new TenantAuthentication(tenant.get()));
        }
        chain.doFilter(request, response);
    }

    private static Optional<String> extractKey(HttpServletRequest request) {
        String auth = request.getHeader("Authorization");
        if (auth != null && auth.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return Optional.of(auth.substring(7).trim()).filter(s -> !s.isEmpty());
        }
        return Optional.ofNullable(request.getHeader("X-API-Key")).map(String::trim).filter(s -> !s.isEmpty());
    }
}
