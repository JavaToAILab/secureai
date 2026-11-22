package io.github.javatoailab.secureai.audit;

/** Somewhere audit records are shipped to after they are sealed. */
public interface AuditSink {

    void write(AuditRecord record);
}
