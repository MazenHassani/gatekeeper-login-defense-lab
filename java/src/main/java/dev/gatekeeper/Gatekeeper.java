package dev.gatekeeper;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.LongSupplier;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Pre-authentication admission only. ALLOW is never authentication or authorization. */
public final class Gatekeeper {
    public enum Reason { ALLOW, SOURCE_RATE, PAIR_FAILURES, STORE_CAPACITY, STORE_ERROR, BUSY, INVALID_INPUT }
    public enum Outcome { SUCCESS, INVALID_CREDENTIALS, ERROR }
    public record Metrics(long evaluated, long admitted, long denied, long policyDenied, long wouldDeny,
                          long capacityDenied, long storeErrors, long busy, long invalidInput,
                          long successes, long credentialFailures, long errors, int inFlight) {}
    private final Policy policy;
    private final AdmissionStore store;
    private final LongSupplier clock;
    private final Semaphore budget;
    private final ThreadLocal<Mac> hmac;
    private final LongAdder evaluated = new LongAdder(), admitted = new LongAdder(), deniedCount = new LongAdder(), policyDenied = new LongAdder(),
            wouldDeny = new LongAdder(), capacityDenied = new LongAdder(), storeErrors = new LongAdder(),
            busy = new LongAdder(), invalidInput = new LongAdder(), successes = new LongAdder(),
            credentialFailures = new LongAdder(), errors = new LongAdder();

    public Gatekeeper(Policy policy, AdmissionStore store) { this(policy, store, System::nanoTime); }
    /** Shared-secret form for coordinated instances; changing the secret resets pseudonymous identity. */
    public Gatekeeper(Policy policy, AdmissionStore store, byte[] sharedKey) {
        this(policy, store, System::nanoTime, sharedKey);
    }
    /** Injectable monotonic clock for deterministic tests; never use a wall clock. */
    public Gatekeeper(Policy policy, AdmissionStore store, LongSupplier clock) {
        this(policy, localOnly(store), clock, randomKey());
    }
    private static AdmissionStore localOnly(AdmissionStore store) {
        if (Objects.requireNonNull(store).requiresSharedIdentity()) {
            throw new IllegalArgumentException("Shared backend requires an explicit shared HMAC key");
        }
        return store;
    }
    private static byte[] randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }
    public Gatekeeper(Policy policy, AdmissionStore store, LongSupplier clock, byte[] sharedKey) {
        this.policy = Objects.requireNonNull(policy);
        this.store = Objects.requireNonNull(store);
        this.clock = Objects.requireNonNull(clock);
        this.budget = new Semaphore(policy.maxConcurrentVerifications());
        if (sharedKey == null || sharedKey.length < 32 || sharedKey.length > 64) {
            throw new IllegalArgumentException("HMAC key must be 32..64 random bytes");
        }
        byte[] key = sharedKey.clone();
        // No thread-local per-request identities; only a keyed digest instance per calling thread.
        this.hmac = ThreadLocal.withInitial(() -> {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(key, "HmacSHA256"));
                return mac;
            } catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
        });
    }

    /**
     * source must come from the actual peer or explicitly trusted proxy resolution.
     * account must use the application's canonical username normalization, before user lookup.
     * Neither a client fingerprint nor a "known device" request field can bypass this gate.
     */
    public Attempt admit(InetAddress source, String account) {
        evaluated.increment();
        if (source == null || account == null || account.isBlank() || account.length() > 256
                || account.getBytes(StandardCharsets.UTF_8).length > 256) {
            invalidInput.increment();
            return denied(Reason.INVALID_INPUT);
        }
        String ip = source.getHostAddress();
        AdmissionStore.Ticket ticket;
        try {
            ticket = Objects.requireNonNull(store.inspectAndRecord("s:" + digest(ip),
                    "p:" + digest(ip + "\u0000" + account), clock.getAsLong(), policy));
            Objects.requireNonNull(ticket.status());
        } catch (RuntimeException e) {
            storeErrors.increment();
            return denied(Reason.STORE_ERROR);
        }
        if (ticket.status() == AdmissionStore.Status.CAPACITY) {
            capacityDenied.increment();
            return denied(Reason.STORE_CAPACITY);
        }
        Reason policyReason = switch (ticket.status()) {
            case SOURCE_RATE -> Reason.SOURCE_RATE;
            case PAIR_FAILURES -> Reason.PAIR_FAILURES;
            default -> Reason.ALLOW;
        };
        if (policyReason != Reason.ALLOW) {
            if (policy.mode() == Policy.Mode.ENFORCE) {
                policyDenied.increment();
                return denied(policyReason);
            }
            wouldDeny.increment();
        }
        if (!budget.tryAcquire()) {
            busy.increment();
            return denied(Reason.BUSY);
        }
        admitted.increment();
        return new Attempt(Reason.ALLOW, policyReason, ticket, true);
    }

    private String digest(String value) {
        return HexFormat.of().formatHex(hmac.get().doFinal(value.getBytes(StandardCharsets.UTF_8)));
    }
    private Attempt denied(Reason reason) { deniedCount.increment(); return new Attempt(reason, reason, null, false); }
    public Metrics metrics() {
        return new Metrics(evaluated.sum(), admitted.sum(), deniedCount.sum(), policyDenied.sum(), wouldDeny.sum(),
                capacityDenied.sum(), storeErrors.sum(), busy.sum(), invalidInput.sum(), successes.sum(),
                credentialFailures.sum(), errors.sum(), policy.maxConcurrentVerifications() - budget.availablePermits());
    }

    /** A one-shot password-work permit. Use try-with-resources; do not transfer work beyond its lifetime. */
    public final class Attempt implements AutoCloseable {
        private final Reason reason, observedReason;
        private final AdmissionStore.Ticket ticket;
        private final boolean allowed;
        private final AtomicBoolean finished = new AtomicBoolean();
        private Attempt(Reason reason, Reason observedReason, AdmissionStore.Ticket ticket, boolean allowed) {
            this.reason = reason; this.observedReason = observedReason; this.ticket = ticket; this.allowed = allowed;
        }
        public boolean allowed() { return allowed && !finished.get(); }
        /** Internal diagnostic; do not disclose policy details on a public login response. */
        public Reason reason() { return reason; }
        public Reason observedReason() { return observedReason; }
        public void complete(Outcome outcome) {
            Objects.requireNonNull(outcome);
            if (!allowed || !finished.compareAndSet(false, true)) return;
            try {
                switch (outcome) {
                    case SUCCESS -> successes.increment();
                    case INVALID_CREDENTIALS -> {
                        credentialFailures.increment();
                        try { ticket.credentialFailed(clock.getAsLong()); }
                        catch (RuntimeException e) { storeErrors.increment(); }
                    }
                    case ERROR -> errors.increment();
                }
            } finally { budget.release(); }
        }
        /** Unreported/exceptional authentication ends as ERROR, not an invented credential failure. */
        @Override public void close() { complete(Outcome.ERROR); }
    }
}
