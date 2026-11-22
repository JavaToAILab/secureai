package io.github.javatoailab.secureai.pii;

/** Kinds of personal or secret data the gateway recognises. The name doubles as the placeholder prefix. */
public enum PiiType {
    EMAIL,
    PHONE,
    SSN,
    CREDIT_CARD,
    IBAN,
    IP_ADDRESS,
    API_KEY
}
