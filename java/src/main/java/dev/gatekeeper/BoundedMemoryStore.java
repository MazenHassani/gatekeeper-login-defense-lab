package dev.gatekeeper;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/** Fixed windows with no eviction of live entries: capacity exhaustion denies admission. */
public final class BoundedMemoryStore implements AdmissionStore {
    private static final class Entry {
        final long started;
        final long ttl;
        int attempts;
        int failures;
        Entry(long started, long ttl) { this.started = started; this.ttl = ttl; }
        boolean expired(long now) { return now - started >= ttl; }
    }
    private final Map<String, Entry> entries = new HashMap<>();
    private final int maximumEntries;
    private long lastSweep;
    private boolean initialized;
    private String signature;

    public BoundedMemoryStore(int maximumEntries) {
        if (maximumEntries < 2 || maximumEntries > 1_000_000) {
            throw new IllegalArgumentException("maximumEntries must be 2..1000000");
        }
        this.maximumEntries = maximumEntries;
    }

    @Override public synchronized Ticket inspectAndRecord(String sourceKey, String pairKey,
                                                           long now, Policy policy) {
        String requested = policy.sourceAttempts() + ":" + policy.pairFailures() + ":" + policy.window().toNanos();
        if (signature != null && !signature.equals(requested)) throw new IllegalArgumentException("Store policy mismatch");
        signature = requested;
        // Public SPI is not a request boundary; still reject unbounded external key material.
        if (sourceKey == null || pairKey == null || sourceKey.equals(pairKey)
                || sourceKey.length() > 128 || pairKey.length() > 128) {
            throw new IllegalArgumentException("distinct bounded store keys required");
        }
        if (!initialized || now - lastSweep >= 1_000_000_000L) {
            sweep(now);
        }
        Entry source = live(sourceKey, now);
        Entry pair = live(pairKey, now);
        int required = (source == null ? 1 : 0) + (pair == null ? 1 : 0);
        if (entries.size() + required > maximumEntries) {
            sweep(now);
            if (entries.size() + required > maximumEntries) return ticket(Status.CAPACITY, null, null);
        }
        if (source == null) {
            source = new Entry(now, policy.window().toNanos());
            entries.put(sourceKey, source);
        }
        // Reject before allocating arbitrary new account keys if this source is already limited.
        if (source.attempts >= policy.sourceAttempts()) return ticket(Status.SOURCE_RATE, pairKey, pair);
        source.attempts++;
        if (pair == null) {
            pair = new Entry(now, policy.window().toNanos());
            entries.put(pairKey, pair);
        }
        return ticket(pair.failures >= policy.pairFailures() ? Status.PAIR_FAILURES : Status.PASS,
                      pairKey, pair);
    }

    private Entry live(String key, long now) {
        Entry entry = entries.get(key);
        if (entry != null && entry.expired(now)) {
            entries.remove(key);
            return null;
        }
        return entry;
    }
    private void sweep(long now) {
        entries.values().removeIf(entry -> entry.expired(now));
        initialized = true;
        lastSweep = now;
    }
    private Ticket ticket(Status status, String key, Entry entry) {
        return new Ticket() {
            private final AtomicBoolean recorded = new AtomicBoolean();
            @Override public Status status() { return status; }
            @Override public void credentialFailed(long now) {
                if (status == Status.CAPACITY || entry == null || !recorded.compareAndSet(false, true)) return;
                synchronized (BoundedMemoryStore.this) {
                    if (entries.get(key) == entry && !entry.expired(now) && entry.failures < Integer.MAX_VALUE) {
                        entry.failures++;
                    }
                }
            }
        };
    }
    /** Number of retained entries; expired entries are removed on later admissions. */
    public synchronized int size() { return entries.size(); }
}
