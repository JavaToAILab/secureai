package io.github.javatoailab.secureai.audit;

import java.time.Instant;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * A sequenced, hash-chained audit entry. {@code hash} covers every field plus {@code prevHash}, so
 * editing, deleting or reordering any record breaks the chain from that point on.
 */
public record AuditRecord(long seq, Instant timestamp, AuditEvent event, String prevHash, String hash) {

    public static final String GENESIS = "0".repeat(64);

    /** Stable text form that is hashed. Map keys are sorted so the hash never depends on iteration order. */
    static String canonical(long seq, Instant timestamp, AuditEvent e, String prevHash) {
        return String.join("|",
                Long.toString(seq),
                timestamp.toString(),
                nz(e.requestId()), nz(e.tenant()), nz(e.region()), nz(e.upstreamHost()), nz(e.model()),
                e.decision().name(),
                new TreeMap<>(e.piiInRequest()).toString(),
                new TreeMap<>(e.piiInResponse()).toString(),
                Double.toString(e.injectionScore()),
                e.injectionSignals().stream().collect(Collectors.joining(",")),
                nz(e.promptSha256()),
                Long.toString(e.latencyMs()),
                prevHash);
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
