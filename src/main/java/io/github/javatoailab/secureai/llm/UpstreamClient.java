package io.github.javatoailab.secureai.llm;

import io.github.javatoailab.secureai.routing.Route;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.json.JsonMapper;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;

/**
 * Forwards a vetted request to an OpenAI-compatible endpoint (Ollama, vLLM, OpenAI, Azure OpenAI
 * behind a compatible proxy). Only requests that passed every check reach this class.
 */
public class UpstreamClient {

    private final RestClient rest;
    private final Map<String, String> apiKeysByBaseUrl;
    private final JsonMapper json;

    public UpstreamClient(Duration connectTimeout, Duration readTimeout, Map<String, String> apiKeysByBaseUrl,
                          JsonMapper json) {
        this.json = json;
        HttpClient http = HttpClient.newBuilder().connectTimeout(connectTimeout).build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(http);
        factory.setReadTimeout(readTimeout);
        this.rest = RestClient.builder().requestFactory(factory).build();
        this.apiKeysByBaseUrl = Map.copyOf(apiKeysByBaseUrl);
    }

    public ChatCompletionResponse complete(Route route, ChatCompletionRequest request) {
        String apiKey = apiKeysByBaseUrl.get(route.baseUrl().toString());
        return rest.post()
                .uri(route.baseUrl().resolve("/v1/chat/completions"))
                .contentType(MediaType.APPLICATION_JSON)
                .headers(h -> {
                    if (apiKey != null && !apiKey.isBlank()) {
                        h.setBearerAuth(apiKey);
                    }
                })
                // Serialised up front so the request carries a Content-Length: some model servers
                // and corporate proxies reject chunked request bodies.
                .body(json.writeValueAsBytes(request))
                .retrieve()
                .body(ChatCompletionResponse.class);
    }
}
