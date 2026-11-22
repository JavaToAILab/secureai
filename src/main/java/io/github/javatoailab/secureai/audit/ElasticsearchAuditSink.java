package io.github.javatoailab.secureai.audit;

import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Indexes each record into Elasticsearch with the plain REST API, using the sequence number as the
 * document id so a retried write cannot create a duplicate.
 */
public final class ElasticsearchAuditSink implements AuditSink {

    private final URI indexUri;
    private final JsonMapper json;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();

    public ElasticsearchAuditSink(URI baseUrl, String index, JsonMapper json) {
        this.indexUri = baseUrl.resolve("/" + index + "/_doc/");
        this.json = json;
    }

    @Override
    public void write(AuditRecord record) {
        HttpRequest request = HttpRequest.newBuilder(indexUri.resolve(Long.toString(record.seq())))
                .timeout(Duration.ofSeconds(3))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(record)))
                .build();
        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 300) {
                throw new IllegalStateException("Elasticsearch returned " + response.statusCode());
            }
        } catch (IOException e) {
            throw new IllegalStateException("Elasticsearch unreachable: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted writing audit record", e);
        }
    }
}
