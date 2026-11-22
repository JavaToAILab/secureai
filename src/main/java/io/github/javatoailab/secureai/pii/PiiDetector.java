package io.github.javatoailab.secureai.pii;

import java.util.List;

/**
 * Finds PII in text. Implementations must return non-overlapping matches sorted by start offset.
 *
 * <p>The default is {@link RegexPiiDetector}: pattern plus checksum, deterministic and fast.
 * A model-based detector (names, addresses) can sit behind the same interface.
 */
public interface PiiDetector {

    List<PiiMatch> detect(String text);
}
