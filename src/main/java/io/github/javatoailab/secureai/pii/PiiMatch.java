package io.github.javatoailab.secureai.pii;

/**
 * One finding in a piece of text. {@code start} is inclusive, {@code end} exclusive.
 * The value is kept in memory only for the length of the request and is never logged or audited.
 */
public record PiiMatch(PiiType type, int start, int end, String value) {

    public PiiMatch {
        if (start < 0 || end <= start) {
            throw new IllegalArgumentException("bad span " + start + ".." + end);
        }
    }

    boolean overlaps(PiiMatch other) {
        return start < other.end && other.start < end;
    }
}
