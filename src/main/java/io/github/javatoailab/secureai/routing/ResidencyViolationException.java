package io.github.javatoailab.secureai.routing;

/** Thrown when no upstream is approved for a tenant's region. The gateway fails closed. */
public class ResidencyViolationException extends RuntimeException {

    public ResidencyViolationException(String message) {
        super(message);
    }
}
