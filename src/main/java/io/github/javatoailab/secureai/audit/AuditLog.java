package io.github.javatoailab.secureai.audit;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Seals events into a hash chain and fans them out to the configured sinks.
 *
 * <p>Appends are serialised: the chain needs a total order, and audit volume is far below the
 * point where one lock matters. A sink failure is logged and counted but does not fail the user's
 * request; the chain still records the event and {@code /admin/audit/verify} reports the gap.
 */
public final class AuditLog {

    private static final System.Logger LOG = System.getLogger(AuditLog.class.getName());

    private final List<AuditSink> sinks;
    private final Clock clock;
    private final int retained;
    private final Deque<AuditRecord> recent = new ArrayDeque<>();
    private final AtomicLong sinkFailures = new AtomicLong();
    private long nextSeq = 1;
    private String lastHash = AuditRecord.GENESIS;

    public AuditLog(List<AuditSink> sinks, Clock clock, int retained) {
        this.sinks = List.copyOf(sinks);
        this.clock = clock;
        this.retained = retained;
    }

    public synchronized AuditRecord append(AuditEvent event) {
        long seq = nextSeq++;
        Instant now = clock.instant();
        String hash = Hashing.sha256(AuditRecord.canonical(seq, now, event, lastHash));
        AuditRecord record = new AuditRecord(seq, now, event, lastHash, hash);
        lastHash = hash;
        recent.addLast(record);
        if (recent.size() > retained) {
            recent.removeFirst();
        }
        for (AuditSink sink : sinks) {
            try {
                sink.write(record);
            } catch (RuntimeException e) {
                sinkFailures.incrementAndGet();
                LOG.log(System.Logger.Level.ERROR, "audit sink " + sink.getClass().getSimpleName()
                        + " failed for seq " + seq, e);
            }
        }
        return record;
    }

    public synchronized List<AuditRecord> recent() {
        return new ArrayList<>(recent);
    }

    public long sinkFailures() {
        return sinkFailures.get();
    }

    /**
     * Recomputes every hash in {@code records} (which must be consecutive) and returns the sequence
     * number of the first record that does not match, if any.
     */
    public static Optional<Long> firstBrokenLink(List<AuditRecord> records) {
        String expectedPrev = records.isEmpty() ? null : records.getFirst().prevHash();
        for (AuditRecord r : records) {
            String recomputed = Hashing.sha256(AuditRecord.canonical(r.seq(), r.timestamp(), r.event(), r.prevHash()));
            if (!r.prevHash().equals(expectedPrev) || !recomputed.equals(r.hash())) {
                return Optional.of(r.seq());
            }
            expectedPrev = r.hash();
        }
        return Optional.empty();
    }
}
