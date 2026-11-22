package io.github.javatoailab.secureai.injection;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Weighted rules for the injection patterns seen most often in practice. Each rule that fires adds
 * its weight; the score is capped at 1.0. Text is normalised first (Unicode NFKC, zero-width
 * characters removed, whitespace collapsed) so "ig​nore previous" is caught too.
 *
 * <p>Heuristics are a floor, not a ceiling: they stop the obvious attacks cheaply and explain
 * themselves. They will miss novel phrasing, which is why the detector sits behind an interface.
 */
public final class HeuristicInjectionDetector implements InjectionDetector {

    private record Rule(String name, double weight, Pattern pattern) {
    }

    private static final int FLAGS = Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE;

    private static final List<Rule> RULES = List.of(
            new Rule("override-instructions", 0.6, Pattern.compile(
                    "\\b(ignore|disregard|forget|override|bypass)\\b.{0,40}\\b(previous|prior|above|earlier|all|your|system)\\b.{0,30}\\b(instructions?|rules|prompts?|directions|guidelines|context)\\b", FLAGS)),
            new Rule("reveal-system-prompt", 0.5, Pattern.compile(
                    "\\b(reveal|show|print|repeat|output|tell me|what (is|are))\\b.{0,40}\\b(system|hidden|initial|original)\\s+(prompt|instructions?|message)\\b", FLAGS)),
            new Rule("role-reassignment", 0.4, Pattern.compile(
                    "\\b(you are now|from now on,? you|act as|pretend (to be|you are)|roleplay as)\\b.{0,60}\\b(unrestricted|unfiltered|no (rules|limits|restrictions)|jailbroken|developer mode|DAN)\\b", FLAGS)),
            new Rule("known-jailbreak", 0.5, Pattern.compile(
                    "\\b(DAN|do anything now|developer mode (enabled|on)|jailbreak(ed)?|AIM mode)\\b", FLAGS)),
            new Rule("fake-role-delimiter", 0.4, Pattern.compile(
                    "(^|\\n)\\s*(#{2,}|\\[|<\\|?|<<)\\s*(system|assistant|im_start|inst)\\b", FLAGS)),
            new Rule("disable-safety", 0.4, Pattern.compile(
                    "\\b(disable|turn off|remove|without)\\b.{0,20}\\b(safety|guardrails?|filters?|content polic(y|ies)|moderation)\\b", FLAGS)),
            new Rule("exfiltration", 0.3, Pattern.compile(
                    "\\b(send|post|upload|exfiltrate|leak)\\b.{0,40}\\b(to|at)\\b.{0,10}(https?://|\\b[\\w-]+\\.(com|net|io|ru)\\b)", FLAGS)),
            new Rule("encoded-payload", 0.2, Pattern.compile(
                    "\\b(base64|rot13|hex)\\b.{0,30}\\b(decode|decoded|execute|follow)\\b|[A-Za-z0-9+/]{120,}={0,2}", FLAGS)));

    private static final Pattern INVISIBLE = Pattern.compile("[\\u200B-\\u200F\\u2060\\uFEFF\\u00AD]");

    @Override
    public InjectionVerdict inspect(String text) {
        if (text == null || text.isBlank()) {
            return InjectionVerdict.CLEAN;
        }
        String normalised = normalise(text);
        double score = 0;
        List<String> signals = new ArrayList<>();
        for (Rule rule : RULES) {
            if (rule.pattern().matcher(normalised).find()) {
                score += rule.weight();
                signals.add(rule.name());
            }
        }
        if (!INVISIBLE.matcher(text).results().limit(3).toList().isEmpty() && !signals.isEmpty()) {
            // Hiding an instruction behind zero-width characters is itself a strong tell.
            score += 0.2;
            signals.add("invisible-characters");
        }
        return signals.isEmpty() ? InjectionVerdict.CLEAN : new InjectionVerdict(Math.min(1.0, score), List.copyOf(signals));
    }

    static String normalise(String text) {
        String n = Normalizer.normalize(text, Normalizer.Form.NFKC);
        n = INVISIBLE.matcher(n).replaceAll("");
        return n.replaceAll("[ \\t]+", " ");
    }
}
