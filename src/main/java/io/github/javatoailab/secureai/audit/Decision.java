package io.github.javatoailab.secureai.audit;

/** What the gateway did with a request. */
public enum Decision {
    FORWARDED,
    FORWARDED_REDACTED,
    BLOCKED_INJECTION,
    BLOCKED_PII,
    BLOCKED_RESIDENCY,
    UPSTREAM_ERROR
}
