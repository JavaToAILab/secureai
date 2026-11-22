package io.github.javatoailab.secureai.pii;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RedactorTest {

    private final Redactor redactor = new Redactor(new RegexPiiDetector());

    @Test
    void replacesPiiWithStablePlaceholders() {
        RedactionVault vault = new RedactionVault();
        Redactor.Result r = redactor.redact("jane@example.com wrote to bob@example.com, then jane@example.com again", vault);

        assertThat(r.text()).isEqualTo("<EMAIL_1> wrote to <EMAIL_2>, then <EMAIL_1> again");
        assertThat(r.counts()).containsEntry(PiiType.EMAIL, 3);
        assertThat(vault.size()).isEqualTo(2);
    }

    @Test
    void placeholdersAreSharedAcrossMessagesOfOneRequest() {
        RedactionVault vault = new RedactionVault();
        redactor.redact("Customer SSN is 123-45-6789", vault);
        Redactor.Result second = redactor.redact("Confirm 123-45-6789 matches", vault);

        assertThat(second.text()).isEqualTo("Confirm <SSN_1> matches");
    }

    @Test
    void rehydrateRestoresOriginalsAndLeavesUnknownPlaceholders() {
        RedactionVault vault = new RedactionVault();
        redactor.redact("Email jane@example.com", vault);

        assertThat(vault.rehydrate("I emailed <EMAIL_1> and <EMAIL_9>."))
                .isEqualTo("I emailed jane@example.com and <EMAIL_9>.");
    }

    @Test
    void textWithoutPiiIsUntouched() {
        Redactor.Result r = redactor.redact("nothing to see", new RedactionVault());
        assertThat(r.changed()).isFalse();
        assertThat(r.text()).isEqualTo("nothing to see");
    }
}
