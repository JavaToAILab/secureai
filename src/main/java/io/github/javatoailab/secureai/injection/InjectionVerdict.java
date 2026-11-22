package io.github.javatoailab.secureai.injection;

import java.util.List;

/**
 * Outcome of an injection check. {@code score} is in [0, 1]; {@code signals} names the rules that
 * fired so an operator can see why a request was blocked without the gateway storing the prompt.
 */
public record InjectionVerdict(double score, List<String> signals) {

    public static final InjectionVerdict CLEAN = new InjectionVerdict(0.0, List.of());

    public boolean exceeds(double threshold) {
        return score >= threshold;
    }
}
