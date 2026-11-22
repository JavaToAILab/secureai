package io.github.javatoailab.secureai.pii;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Per-request mapping between placeholders such as {@code <EMAIL_1>} and the original values.
 *
 * <p>The same value always gets the same placeholder within a request, so the model can still
 * reason about "the customer at &lt;EMAIL_1&gt;" across messages. The vault lives only for the
 * request; nothing in it is persisted or logged.
 */
public final class RedactionVault {

    private static final Pattern PLACEHOLDER = Pattern.compile("<([A-Z_]+)_(\\d+)>");

    private final Map<String, String> valueToPlaceholder = new LinkedHashMap<>();
    private final Map<String, String> placeholderToValue = new LinkedHashMap<>();
    private final Map<PiiType, Integer> counters = new LinkedHashMap<>();

    String placeholderFor(PiiType type, String value) {
        return valueToPlaceholder.computeIfAbsent(value, v -> {
            int n = counters.merge(type, 1, Integer::sum);
            String placeholder = "<" + type.name() + "_" + n + ">";
            placeholderToValue.put(placeholder, v);
            return placeholder;
        });
    }

    /** Puts the original values back into model output. Unknown placeholders are left as they are. */
    public String rehydrate(String text) {
        if (text == null || placeholderToValue.isEmpty()) {
            return text;
        }
        Matcher m = PLACEHOLDER.matcher(text);
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            String original = placeholderToValue.get(m.group());
            m.appendReplacement(out, Matcher.quoteReplacement(original != null ? original : m.group()));
        }
        m.appendTail(out);
        return out.toString();
    }

    public int size() {
        return placeholderToValue.size();
    }
}
