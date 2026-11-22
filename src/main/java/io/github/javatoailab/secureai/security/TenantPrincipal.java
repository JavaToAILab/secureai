package io.github.javatoailab.secureai.security;

import io.github.javatoailab.secureai.config.PiiAction;
import io.github.javatoailab.secureai.routing.Region;

/** The authenticated caller, with the policy that applies to it. */
public record TenantPrincipal(String id, Region region, PiiAction piiAction, double injectionThreshold, boolean admin) {
}
