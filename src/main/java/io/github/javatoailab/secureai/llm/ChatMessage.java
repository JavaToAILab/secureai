package io.github.javatoailab.secureai.llm;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ChatMessage(String role, String content) {

    public ChatMessage withContent(String newContent) {
        return new ChatMessage(role, newContent);
    }

    /** Text that came from outside the calling application and so may carry an injection. */
    @JsonIgnore
    public boolean isUntrusted() {
        return "user".equals(role) || "tool".equals(role);
    }
}
