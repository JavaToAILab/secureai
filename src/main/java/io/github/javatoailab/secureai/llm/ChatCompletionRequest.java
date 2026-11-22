package io.github.javatoailab.secureai.llm;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/** The subset of the OpenAI chat-completions request the gateway understands and forwards. */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ChatCompletionRequest(
        String model,
        List<ChatMessage> messages,
        Double temperature,
        @JsonProperty("max_tokens") Integer maxTokens,
        Boolean stream) {

    public ChatCompletionRequest withMessages(List<ChatMessage> newMessages) {
        return new ChatCompletionRequest(model, newMessages, temperature, maxTokens, stream);
    }

    public ChatCompletionRequest withModel(String newModel) {
        return new ChatCompletionRequest(newModel, messages, temperature, maxTokens, stream);
    }
}
