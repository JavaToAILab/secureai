package io.github.javatoailab.secureai.pii;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RegexPiiDetectorTest {

    private final RegexPiiDetector detector = new RegexPiiDetector();

    private List<PiiType> types(String text) {
        return detector.detect(text).stream().map(PiiMatch::type).toList();
    }

    @Test
    void findsCommonIdentifiers() {
        assertThat(types("Mail jane.doe@example.com or call (469) 555-0142")).containsExactly(PiiType.EMAIL, PiiType.PHONE);
        assertThat(types("SSN 123-45-6789 on file")).containsExactly(PiiType.SSN);
        assertThat(types("from 10.20.30.40")).containsExactly(PiiType.IP_ADDRESS);
    }

    @Test
    void cardNumbersMustPassLuhn() {
        assertThat(types("card 4111 1111 1111 1111")).containsExactly(PiiType.CREDIT_CARD);
        assertThat(types("order 4111 1111 1111 1112")).doesNotContain(PiiType.CREDIT_CARD);
    }

    @Test
    void ibanMustPassMod97() {
        assertThat(types("pay DE89 3704 0044 0532 0130 00 today")).containsExactly(PiiType.IBAN);
        assertThat(types("pay DE00 3704 0044 0532 0130 00 today")).doesNotContain(PiiType.IBAN);
    }

    @Test
    void ssnRulesRejectNumbersNeverIssued() {
        assertThat(types("000-12-3456")).isEmpty();
        assertThat(types("666-12-3456")).isEmpty();
        assertThat(types("123-00-4567")).isEmpty();
    }

    @Test
    void secretsAreCaughtAndNotDoubleCounted() {
        List<PiiMatch> matches = detector.detect("key sk-proj-AbCdEf0123456789XyZaBcDeF here");
        assertThat(matches).singleElement().extracting(PiiMatch::type).isEqualTo(PiiType.API_KEY);
    }

    @Test
    void cleanTextHasNoFindings() {
        assertThat(detector.detect("Summarise the Q3 incident review for the payments team.")).isEmpty();
    }
}
