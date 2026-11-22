package io.github.javatoailab.secureai.audit;

import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/** Appends one JSON object per line. Simple to ship with any log forwarder, and easy to verify offline. */
public final class JsonLinesAuditSink implements AuditSink {

    private final Path file;
    private final JsonMapper json;

    public JsonLinesAuditSink(Path file, JsonMapper json) {
        this.file = file;
        this.json = json;
        try {
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public synchronized void write(AuditRecord record) {
        try {
            Files.writeString(file, json.writeValueAsString(record) + "\n", StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
