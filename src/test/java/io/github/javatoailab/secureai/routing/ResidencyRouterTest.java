package io.github.javatoailab.secureai.routing;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ResidencyRouterTest {

    @Test
    void routesToTheRegionsOwnEndpoint() {
        Route us = new Route(Region.US, URI.create("http://us.llm"), "m-us");
        Route eu = new Route(Region.EU, URI.create("http://eu.llm"), "m-eu");
        ResidencyRouter router = new ResidencyRouter(Map.of(Region.US, us, Region.EU, eu));

        assertThat(router.routeFor(Region.EU)).isEqualTo(eu);
    }

    @Test
    void failsClosedWhenARegionHasNoApprovedEndpoint() {
        ResidencyRouter router = new ResidencyRouter(Map.of(
                Region.US, new Route(Region.US, URI.create("http://us.llm"), "m")));

        assertThatThrownBy(() -> router.routeFor(Region.EU))
                .isInstanceOf(ResidencyViolationException.class)
                .hasMessageContaining("EU");
    }
}
