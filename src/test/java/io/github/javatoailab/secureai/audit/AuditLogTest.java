package io.github.javatoailab.secureai.audit;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AuditLogTest {

    private final Clock clock = Clock.fixed(Instant.parse("2026-11-21T12:00:00Z"), ZoneOffset.UTC);

    private static AuditEvent event(String id, Decision d) {
        return new AuditEvent(id, "t1", "US", "llm.local", "m", d, Map.of(), Map.of(), 0.0, List.of(), "abc", 5);
    }

    @Test
    void recordsFormAnIntactChain() {
        AuditLog log = new AuditLog(List.of(), clock, 100);
        AuditRecord first = log.append(event("a", Decision.FORWARDED));
        AuditRecord second = log.append(event("b", Decision.BLOCKED_INJECTION));

        assertThat(first.prevHash()).isEqualTo(AuditRecord.GENESIS);
        assertThat(second.prevHash()).isEqualTo(first.hash());
        assertThat(AuditLog.firstBrokenLink(log.recent())).isEmpty();
    }

    @Test
    void editingARecordBreaksTheChainAtThatRecord() {
        AuditLog log = new AuditLog(List.of(), clock, 100);
        log.append(event("a", Decision.FORWARDED));
        log.append(event("b", Decision.BLOCKED_PII));
        log.append(event("c", Decision.FORWARDED));

        List<AuditRecord> records = new ArrayList<>(log.recent());
        AuditRecord original = records.get(1);
        AuditRecord forged = new AuditRecord(original.seq(), original.timestamp(),
                event("b", Decision.FORWARDED), original.prevHash(), original.hash());
        records.set(1, forged);

        assertThat(AuditLog.firstBrokenLink(records)).contains(2L);
    }

    @Test
    void deletingARecordIsDetected() {
        AuditLog log = new AuditLog(List.of(), clock, 100);
        log.append(event("a", Decision.FORWARDED));
        log.append(event("b", Decision.FORWARDED));
        log.append(event("c", Decision.FORWARDED));

        List<AuditRecord> records = new ArrayList<>(log.recent());
        records.remove(1);

        assertThat(AuditLog.firstBrokenLink(records)).contains(3L);
    }

    @Test
    void aFailingSinkDoesNotLoseTheRecord() {
        AuditSink broken = r -> {
            throw new IllegalStateException("down");
        };
        AuditLog log = new AuditLog(List.of(broken), clock, 100);
        log.append(event("a", Decision.FORWARDED));

        assertThat(log.recent()).hasSize(1);
        assertThat(log.sinkFailures()).isEqualTo(1);
    }
}
