package io.github.javatoailab.secureai.audit;

import io.github.javatoailab.secureai.pii.PiiType;

import java.util.List;
import java.util.Map;

/**
 * What happened, before it is sequenced and hashed. Note what is absent: no prompt text, no reply
 * text and no PII values. The prompt is represented only by its SHA-256, which proves what was sent
 * when the caller still holds the original, without the audit store becoming a second copy of it.
 */
public record AuditEvent(
        String requestId,
        String tenant,
        String region,
        String upstreamHost,
        String model,
        Decision decision,
        Map<PiiType, Integer> piiInRequest,
        Map<PiiType, Integer> piiInResponse,
        double injectionScore,
        List<String> injectionSignals,
        String promptSha256,
        long latencyMs) {
}
