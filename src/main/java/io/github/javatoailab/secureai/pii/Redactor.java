package io.github.javatoailab.secureai.pii;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/** Replaces detected PII with placeholders recorded in a {@link RedactionVault}. */
public final class Redactor {

    private final PiiDetector detector;

    public Redactor(PiiDetector detector) {
        this.detector = detector;
    }

    public record Result(String text, Map<PiiType, Integer> counts) {
        public boolean changed() {
            return !counts.isEmpty();
        }
    }

    public Result redact(String text, RedactionVault vault) {
        List<PiiMatch> matches = detector.detect(text);
        if (matches.isEmpty()) {
            return new Result(text, Map.of());
        }
        Map<PiiType, Integer> counts = new EnumMap<>(PiiType.class);
        StringBuilder out = new StringBuilder(text.length());
        int cursor = 0;
        for (PiiMatch m : matches) {
            out.append(text, cursor, m.start()).append(vault.placeholderFor(m.type(), m.value()));
            counts.merge(m.type(), 1, Integer::sum);
            cursor = m.end();
        }
        out.append(text.substring(cursor));
        return new Result(out.toString(), Map.copyOf(counts));
    }

    public Map<PiiType, Integer> scan(String text) {
        Map<PiiType, Integer> counts = new EnumMap<>(PiiType.class);
        for (PiiMatch m : detector.detect(text)) {
            counts.merge(m.type(), 1, Integer::sum);
        }
        return counts.isEmpty() ? Map.of() : Map.copyOf(counts);
    }
}
