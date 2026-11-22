package io.github.javatoailab.secureai.security;

import io.github.javatoailab.secureai.audit.Hashing;
import io.github.javatoailab.secureai.config.SecureAiProperties;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Resolves an API key to a tenant by comparing SHA-256 digests in constant time. */
public final class TenantRegistry {

    private record Entry(byte[] keyHash, TenantPrincipal principal) {
    }

    private final List<Entry> entries;

    public TenantRegistry(Map<String, SecureAiProperties.Tenant> tenants) {
        this.entries = tenants.entrySet().stream()
                .map(e -> new Entry(
                        e.getValue().apiKeySha256().toLowerCase().getBytes(StandardCharsets.US_ASCII),
                        new TenantPrincipal(e.getKey(), e.getValue().region(), e.getValue().piiAction(),
                                e.getValue().injectionThreshold(), e.getValue().admin())))
                .toList();
    }

    public Optional<TenantPrincipal> authenticate(String apiKey) {
        byte[] presented = Hashing.sha256(apiKey).getBytes(StandardCharsets.US_ASCII);
        TenantPrincipal found = null;
        for (Entry entry : entries) {
            // Check every entry so timing does not reveal how far down the list a key matched.
            if (MessageDigest.isEqual(entry.keyHash(), presented)) {
                found = entry.principal();
            }
        }
        return Optional.ofNullable(found);
    }
}
