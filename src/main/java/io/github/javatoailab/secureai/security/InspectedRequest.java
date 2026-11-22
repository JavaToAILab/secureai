package io.github.javatoailab.secureai.security;

import io.github.javatoailab.secureai.injection.InjectionVerdict;
import io.github.javatoailab.secureai.llm.ChatCompletionRequest;
import io.github.javatoailab.secureai.pii.PiiType;
import io.github.javatoailab.secureai.pii.RedactionVault;

import java.util.Map;

/**
 * A request that passed inspection, handed from the filter chain to the controller as a request
 * attribute. {@code request} is already redacted; the controller never sees the raw prompt.
 */
public record InspectedRequest(
        String requestId,
        TenantPrincipal tenant,
        ChatCompletionRequest request,
        RedactionVault vault,
        Map<PiiType, Integer> piiCounts,
        InjectionVerdict injection,
        String promptSha256,
        long startNanos) {

    public static final String ATTRIBUTE = "secureai.inspectedRequest";
    public static final String REQUEST_ID_HEADER = "X-SecureAI-Request-Id";
}
