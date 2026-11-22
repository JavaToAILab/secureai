package io.github.javatoailab.secureai.config;

/** What to do when a request contains PII. */
public enum PiiAction {
    /** Replace PII with placeholders before the model sees it, and restore it in the reply. */
    REDACT,
    /** Refuse the request outright. For tenants whose data must never leave in any form. */
    BLOCK
}
