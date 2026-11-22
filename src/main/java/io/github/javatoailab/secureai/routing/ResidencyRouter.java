package io.github.javatoailab.secureai.routing;

import java.util.Map;

/**
 * Picks the upstream for a tenant's residency region. There is deliberately no fallback: if the EU
 * route is missing, an EU tenant's request is refused rather than quietly sent to a US endpoint.
 */
public final class ResidencyRouter {

    private final Map<Region, Route> routes;

    public ResidencyRouter(Map<Region, Route> routes) {
        this.routes = Map.copyOf(routes);
    }

    public Route routeFor(Region region) {
        Route route = routes.get(region);
        if (route == null) {
            throw new ResidencyViolationException("No upstream approved for region " + region);
        }
        return route;
    }
}
