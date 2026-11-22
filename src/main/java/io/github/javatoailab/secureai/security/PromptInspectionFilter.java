package io.github.javatoailab.secureai.security;

import io.github.javatoailab.secureai.audit.AuditEvent;
import io.github.javatoailab.secureai.audit.AuditLog;
import io.github.javatoailab.secureai.audit.Decision;
import io.github.javatoailab.secureai.audit.Hashing;
import io.github.javatoailab.secureai.config.PiiAction;
import io.github.javatoailab.secureai.injection.InjectionDetector;
import io.github.javatoailab.secureai.injection.InjectionVerdict;
import io.github.javatoailab.secureai.llm.ChatCompletionRequest;
import io.github.javatoailab.secureai.llm.ChatMessage;
import io.github.javatoailab.secureai.pii.PiiType;
import io.github.javatoailab.secureai.pii.RedactionVault;
import io.github.javatoailab.secureai.pii.Redactor;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The compliance checkpoint, placed in Spring Security's chain after authentication and
 * authorization. In order:
 *
 * <ol>
 *   <li>Parse the OpenAI-style body; reject anything malformed or streaming.</li>
 *   <li>Score untrusted messages (user, tool) for prompt injection; block at the tenant's threshold.</li>
 *   <li>Scan every message for PII; block or redact according to the tenant's policy.</li>
 * </ol>
 *
 * Every refusal is audited before the response is written. A request that passes continues with
 * the redacted body attached as {@link InspectedRequest}.
 */
public final class PromptInspectionFilter extends OncePerRequestFilter {

    private static final String PATH = "/v1/chat/completions";

    private final JsonMapper json;
    private final InjectionDetector injection;
    private final Redactor redactor;
    private final AuditLog audit;

    public PromptInspectionFilter(JsonMapper json, InjectionDetector injection, Redactor redactor, AuditLog audit) {
        this.json = json;
        this.injection = injection;
        this.redactor = redactor;
        this.audit = audit;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return !("POST".equals(request.getMethod()) && PATH.equals(path));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        long start = System.nanoTime();
        String requestId = UUID.randomUUID().toString();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof TenantPrincipal tenant)) {
            ErrorResponses.write(response, 401, "unauthenticated", "API key required", requestId);
            return;
        }

        byte[] raw = request.getInputStream().readAllBytes();
        String promptHash = Hashing.sha256(new String(raw, StandardCharsets.UTF_8));
        ChatCompletionRequest body;
        try {
            body = json.readValue(raw, ChatCompletionRequest.class);
        } catch (JacksonException e) {
            ErrorResponses.write(response, 400, "invalid_request", "Body is not a valid chat completion request", requestId);
            return;
        }
        if (body.messages() == null || body.messages().isEmpty()
                || body.messages().stream().anyMatch(m -> m.role() == null || m.content() == null)) {
            ErrorResponses.write(response, 400, "invalid_request", "messages must be non-empty, each with role and content", requestId);
            return;
        }
        if (Boolean.TRUE.equals(body.stream())) {
            ErrorResponses.write(response, 400, "unsupported", "Streaming is not supported yet", requestId);
            return;
        }

        InjectionVerdict verdict = worstVerdict(body.messages());
        Map<PiiType, Integer> piiCounts = scanAll(body.messages());

        if (verdict.exceeds(tenant.injectionThreshold())) {
            audit.append(event(requestId, tenant, Decision.BLOCKED_INJECTION, piiCounts, verdict, promptHash, start));
            ErrorResponses.write(response, 400, "prompt_injection",
                    "Request blocked: likely prompt injection", requestId, verdict.signals());
            return;
        }
        if (!piiCounts.isEmpty() && tenant.piiAction() == PiiAction.BLOCK) {
            audit.append(event(requestId, tenant, Decision.BLOCKED_PII, piiCounts, verdict, promptHash, start));
            ErrorResponses.write(response, 422, "pii_not_allowed",
                    "Request blocked: personal data is not allowed for this tenant", requestId,
                    piiCounts.keySet().stream().map(Enum::name).toList());
            return;
        }

        RedactionVault vault = new RedactionVault();
        List<ChatMessage> redacted = new ArrayList<>(body.messages().size());
        for (ChatMessage m : body.messages()) {
            redacted.add(m.withContent(redactor.redact(m.content(), vault).text()));
        }

        request.setAttribute(InspectedRequest.ATTRIBUTE, new InspectedRequest(
                requestId, tenant, body.withMessages(List.copyOf(redacted)), vault, piiCounts, verdict, promptHash, start));
        chain.doFilter(request, response);
    }

    private InjectionVerdict worstVerdict(List<ChatMessage> messages) {
        InjectionVerdict worst = InjectionVerdict.CLEAN;
        for (ChatMessage m : messages) {
            if (m.isUntrusted()) {
                InjectionVerdict v = injection.inspect(m.content());
                if (v.score() > worst.score()) {
                    worst = v;
                }
            }
        }
        return worst;
    }

    private Map<PiiType, Integer> scanAll(List<ChatMessage> messages) {
        Map<PiiType, Integer> total = new EnumMap<>(PiiType.class);
        for (ChatMessage m : messages) {
            redactor.scan(m.content()).forEach((type, n) -> total.merge(type, n, Integer::sum));
        }
        return total.isEmpty() ? Map.of() : Map.copyOf(total);
    }

    private static AuditEvent event(String requestId, TenantPrincipal tenant, Decision decision,
                                    Map<PiiType, Integer> pii, InjectionVerdict verdict, String promptHash, long start) {
        return new AuditEvent(requestId, tenant.id(), tenant.region().name(), null, null, decision,
                pii, Map.of(), verdict.score(), verdict.signals(), promptHash,
                (System.nanoTime() - start) / 1_000_000);
    }
}
