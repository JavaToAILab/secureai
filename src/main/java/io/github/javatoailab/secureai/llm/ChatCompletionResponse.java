package io.github.javatoailab.secureai.llm;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ChatCompletionResponse(
        String id,
        String object,
        Long created,
        String model,
        List<Choice> choices,
        Map<String, Object> usage) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Choice(int index, ChatMessage message, @JsonProperty("finish_reason") String finishReason) {

        public Choice withMessage(ChatMessage newMessage) {
            return new Choice(index, newMessage, finishReason);
        }
    }

    public ChatCompletionResponse withChoices(List<Choice> newChoices) {
        return new ChatCompletionResponse(id, object, created, model, newChoices, usage);
    }
}
