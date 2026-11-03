package dev.gatekeeper;

/**
 * Atomic attempt/failure tracking SPI. An implementation must be thread safe, bounded,
 * use the supplied monotonic time domain, and consume a source attempt even when the
 * pair is failure-limited. A rejected request must not increment credential failures.
 * This release provides and tests only the single-process in-memory implementation.
 */
public interface AdmissionStore {
    /** Shared backends must use the explicit shared-key Gatekeeper constructor. */
    default boolean requiresSharedIdentity() { return false; }
    enum Status { PASS, SOURCE_RATE, PAIR_FAILURES, CAPACITY }
    interface Ticket {
        Status status();
        /** Record one failed credential check, once per ticket, only in its original live window. */
        void credentialFailed(long nowNanos);
    }
    Ticket inspectAndRecord(String sourceKey, String pairKey, long nowNanos, Policy policy);
}
