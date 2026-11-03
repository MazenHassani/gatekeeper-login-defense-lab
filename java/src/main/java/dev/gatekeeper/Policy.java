package dev.gatekeeper;

import java.time.Duration;
import java.util.Objects;

/** Limits apply to one Gatekeeper/store instance, never implicitly to a cluster. */
public record Policy(int sourceAttempts, int pairFailures, Duration window,
                     int maxConcurrentVerifications, Mode mode) {
    public enum Mode { ENFORCE, SHADOW }
    public Policy {
        Objects.requireNonNull(window, "window");
        Objects.requireNonNull(mode, "mode");
        if (sourceAttempts < 1 || pairFailures < 1 || maxConcurrentVerifications < 1
                || window.compareTo(Duration.ofMillis(1)) < 0
                || window.compareTo(Duration.ofDays(1)) > 0
                || !window.equals(Duration.ofMillis(window.toMillis()))) {
            throw new IllegalArgumentException("Positive limits and whole-millisecond window between 1 ms and 1 day required");
        }
    }
}
