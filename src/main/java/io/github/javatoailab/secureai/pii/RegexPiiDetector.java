package io.github.javatoailab.secureai.pii;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pattern-based PII detection with a validator per type, so a 16-digit order number is not
 * mistaken for a card (Luhn) and a random string is not mistaken for an IBAN (mod 97).
 *
 * <p>Rules are tried in declaration order. When two rules match overlapping text, the earlier,
 * more specific rule wins: an API key containing digits is not also reported as a phone number.
 */
public final class RegexPiiDetector implements PiiDetector {

    private record Rule(PiiType type, Pattern pattern, Predicate<String> valid) {
    }

    private static final List<Rule> RULES = List.of(
            new Rule(PiiType.API_KEY,
                    Pattern.compile("\\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[bp]-[A-Za-z0-9-]{20,})\\b"),
                    s -> true),
            new Rule(PiiType.EMAIL,
                    Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"),
                    s -> true),
            new Rule(PiiType.IBAN,
                    Pattern.compile("\\b[A-Z]{2}\\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\\b"),
                    RegexPiiDetector::validIban),
            new Rule(PiiType.CREDIT_CARD,
                    Pattern.compile("\\b(?:\\d[ -]?){12,18}\\d\\b"),
                    RegexPiiDetector::luhn),
            new Rule(PiiType.SSN,
                    Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b"),
                    RegexPiiDetector::validSsn),
            new Rule(PiiType.PHONE,
                    Pattern.compile("(?<![\\w+])(?:\\+\\d{1,3}[ .-]?)?(?:\\(\\d{3}\\)|\\d{3})[ .-]?\\d{3}[ .-]?\\d{4}\\b"),
                    s -> true),
            new Rule(PiiType.IP_ADDRESS,
                    Pattern.compile("\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b"),
                    s -> true));

    @Override
    public List<PiiMatch> detect(String text) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        List<PiiMatch> accepted = new ArrayList<>();
        for (Rule rule : RULES) {
            Matcher m = rule.pattern().matcher(text);
            while (m.find()) {
                PiiMatch candidate = new PiiMatch(rule.type(), m.start(), m.end(), m.group());
                if (rule.valid().test(candidate.value())
                        && accepted.stream().noneMatch(candidate::overlaps)) {
                    accepted.add(candidate);
                }
            }
        }
        accepted.sort(Comparator.comparingInt(PiiMatch::start));
        return List.copyOf(accepted);
    }

    static boolean luhn(String raw) {
        String digits = raw.replaceAll("[ -]", "");
        if (digits.length() < 13 || digits.length() > 19) {
            return false;
        }
        int sum = 0;
        boolean dbl = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int d = digits.charAt(i) - '0';
            if (dbl) {
                d *= 2;
                if (d > 9) {
                    d -= 9;
                }
            }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    static boolean validSsn(String ssn) {
        String[] p = ssn.split("-");
        // SSA never issues area 000, 666 or 900-999, group 00 or serial 0000.
        int area = Integer.parseInt(p[0]);
        return area != 0 && area != 666 && area < 900
                && !p[1].equals("00") && !p[2].equals("0000");
    }

    private static final Map<String, Integer> IBAN_LENGTHS = Map.ofEntries(
            Map.entry("DE", 22), Map.entry("GB", 22), Map.entry("FR", 27), Map.entry("NL", 18),
            Map.entry("ES", 24), Map.entry("IT", 27), Map.entry("IE", 22), Map.entry("BE", 16),
            Map.entry("CH", 21), Map.entry("AT", 20), Map.entry("PL", 28), Map.entry("SE", 24));

    static boolean validIban(String raw) {
        String iban = raw.replace(" ", "");
        Integer expected = IBAN_LENGTHS.get(iban.substring(0, 2));
        if (expected != null && iban.length() != expected) {
            return false;
        }
        String rearranged = iban.substring(4) + iban.substring(0, 4);
        StringBuilder numeric = new StringBuilder();
        for (char c : rearranged.toCharArray()) {
            numeric.append(Character.isLetter(c) ? String.valueOf(c - 'A' + 10) : String.valueOf(c));
        }
        return new BigInteger(numeric.toString()).mod(BigInteger.valueOf(97)).intValue() == 1;
    }
}
