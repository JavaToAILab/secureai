package io.github.javatoailab.secureai.routing;

import java.net.URI;

/** Where a region's traffic goes: an OpenAI-compatible base URL and the model to request there. */
public record Route(Region region, URI baseUrl, String model) {
}
