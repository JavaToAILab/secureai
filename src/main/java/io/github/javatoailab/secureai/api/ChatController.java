package io.github.javatoailab.secureai.api;

import io.github.javatoailab.secureai.audit.AuditEvent;
import io.github.javatoailab.secureai.audit.AuditLog;
import io.github.javatoailab.secureai.audit.Decision;
import io.github.javatoailab.secureai.llm.ChatCompletionResponse;
import io.github.javatoailab.secureai.llm.ChatMessage;
import io.github.javatoailab.secureai.llm.UpstreamClient;
import io.github.javatoailab.secureai.pii.PiiType;
import io.github.javatoailab.secureai.pii.RedactionVault;
import io.github.javatoailab.secureai.pii.Redactor;
import io.github.javatoailab.secureai.routing.ResidencyRouter;
import io.github.javatoailab.secureai.routing.ResidencyViolationException;
import io.github.javatoailab.secureai.routing.Route;
import io.github.javatoailab.secureai.security.InspectedRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * OpenAI-compatible endpoint. By the time a request arrives here it is authenticated, inspected and
 * redacted. This class picks the residency-approved upstream, forwards, then checks the reply:
 * PII the model produced on its own is redacted, and placeholders from the request are restored.
 */
@RestController
public class ChatController {

    private final ResidencyRouter router;
    private final UpstreamClient upstream;
    private final Redactor redactor;
    private final AuditLog audit;

    public ChatController(ResidencyRouter router, UpstreamClient upstream, Redactor redactor, AuditLog audit) {
        this.router = router;
        this.upstream = upstream;
        this.redactor = redactor;
        this.audit = audit;
    }

    @PostMapping("/v1/chat/completions")
    public ResponseEntity<?> complete(@RequestAttribute(InspectedRequest.ATTRIBUTE) InspectedRequest in) {
        Route route;
        try {
            route = router.routeFor(in.tenant().region());
        } catch (ResidencyViolationException e) {
            record(in, null, Decision.BLOCKED_RESIDENCY, Map.of());
            return error(in, 403, "residency_violation", e.getMessage());
        }

        ChatCompletionResponse reply;
        try {
            // The tenant's region decides the model, not the caller.
            reply = upstream.complete(route, in.request().withModel(route.model()));
        } catch (RestClientException e) {
            record(in, route, Decision.UPSTREAM_ERROR, Map.of());
            return error(in, 502, "upstream_error", "Model endpoint for region " + route.region() + " failed");
        }
        if (reply == null || reply.choices() == null) {
            record(in, route, Decision.UPSTREAM_ERROR, Map.of());
            return error(in, 502, "upstream_error", "Model endpoint returned no choices");
        }

        Map<PiiType, Integer> leaked = new EnumMap<>(PiiType.class);
        List<ChatCompletionResponse.Choice> cleaned = new ArrayList<>();
        for (ChatCompletionResponse.Choice choice : reply.choices()) {
            ChatMessage message = choice.message();
            if (message == null || message.content() == null) {
                cleaned.add(choice);
                continue;
            }
            // Scan before restoring: anything found now did not come from the caller's placeholders.
            Redactor.Result scrubbed = redactor.redact(message.content(), new RedactionVault());
            scrubbed.counts().forEach((t, n) -> leaked.merge(t, n, Integer::sum));
            cleaned.add(choice.withMessage(message.withContent(in.vault().rehydrate(scrubbed.text()))));
        }

        boolean redacted = in.vault().size() > 0 || !leaked.isEmpty();
        record(in, route, redacted ? Decision.FORWARDED_REDACTED : Decision.FORWARDED, leaked);
        return ResponseEntity.ok()
                .header(InspectedRequest.REQUEST_ID_HEADER, in.requestId())
                .body(reply.withChoices(cleaned));
    }

    private void record(InspectedRequest in, Route route, Decision decision, Map<PiiType, Integer> piiOut) {
        audit.append(new AuditEvent(
                in.requestId(), in.tenant().id(), in.tenant().region().name(),
                route == null ? null : route.baseUrl().getHost(),
                route == null ? null : route.model(),
                decision, in.piiCounts(), piiOut.isEmpty() ? Map.of() : Map.copyOf(piiOut),
                in.injection().score(), in.injection().signals(), in.promptSha256(),
                (System.nanoTime() - in.startNanos()) / 1_000_000));
    }

    private static ResponseEntity<Map<String, Object>> error(InspectedRequest in, int status, String type, String message) {
        return ResponseEntity.status(status)
                .header(InspectedRequest.REQUEST_ID_HEADER, in.requestId())
                .body(Map.of("error", Map.of("type", type, "message", message, "request_id", in.requestId())));
    }
}
