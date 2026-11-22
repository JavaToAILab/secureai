package io.github.javatoailab.secureai.injection;

/**
 * Scores untrusted text for prompt-injection intent.
 *
 * <p>{@link HeuristicInjectionDetector} is the default. A fine-tuned classifier (for example an
 * ONNX model run in-process) can implement this interface and be combined with it.
 */
public interface InjectionDetector {

    InjectionVerdict inspect(String text);
}
