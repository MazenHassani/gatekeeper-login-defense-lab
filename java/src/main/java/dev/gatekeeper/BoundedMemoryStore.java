package dev.gatekeeper;

import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Fixed windows with no eviction of live entries. Expiry maintenance visits at most
 * 32 indexed entries plus the two requested keys per admission; saturation fails closed.
 */
public final class BoundedMemoryStore implements AdmissionStore {
    private static final int EXPIRY_BUDGET = 32;
    private static final class Entry {
        final String key;
        final long started;
        final long ttl;
        final long deadline;
        int attempts;
        int failures;
        Entry(String key, long started, long ttl, long deadline) {
            this.key = key; this.started = started; this.ttl = ttl; this.deadline = deadline;
        }
        boolean expired(long now) { return now - started >= ttl; }
    }
    /** Low-cardinality diagnostics for checking maintenance work and bounded index retention. */
    public record Maintenance(long expiryInspections, long expiredEntries,
                              int retainedEntries, int expiryIndexEntries) {}
    private final Map<String, Entry> entries;
    // Exactly one index node per retained entry, including when a requested key expires early.
    private final TreeSet<Entry> expiryIndex = new TreeSet<>(
            Comparator.comparingLong((Entry entry) -> entry.deadline).thenComparing(entry -> entry.key));
    private final int maximumEntries;
    private long origin;
    private boolean initialized;
    private long expiryInspections;
    private long expiredEntries;
    private String signature;

    public BoundedMemoryStore(int maximumEntries) {
        if (maximumEntries < 2 || maximumEntries > 1_000_000) {
            throw new IllegalArgumentException("maximumEntries must be 2..1000000");
        }
        this.maximumEntries = maximumEntries;
        entries = new HashMap<>(maximumEntries * 4 / 3 + 1);
        // Allocate the bounded hash table at construction, avoiding table-wide resize during admission.
        entries.put("initial-allocation", null);
        entries.remove("initial-allocation");
    }

    @Override public synchronized Ticket inspectAndRecord(String sourceKey, String pairKey,
                                                           long now, Policy policy) {
        String requested = policy.sourceAttempts() + ":" + policy.pairFailures() + ":" + policy.window().toNanos();
        if (signature != null && !signature.equals(requested)) throw new IllegalArgumentException("Store policy mismatch");
        // Public SPI is not a request boundary; still reject unbounded external key material.
        if (sourceKey == null || pairKey == null || sourceKey.equals(pairKey)
                || sourceKey.length() > 128 || pairKey.length() > 128) {
            throw new IllegalArgumentException("distinct bounded store keys required");
        }
        signature = requested;
        if (!initialized) { origin = now; initialized = true; }
        // A concurrent caller can sample time before another caller initializes the
        // origin, then acquire this lock later. Negative relative samples are valid.
        long ttl = policy.window().toNanos();
        long deadline = Math.addExact(now - origin, ttl);
        pruneExpired(now);
        Entry source = live(sourceKey, now);
        Entry pair = live(pairKey, now);
        // Reject before allocating arbitrary new account keys if this source is already limited.
        if (source != null && source.attempts >= policy.sourceAttempts()) {
            return ticket(Status.SOURCE_RATE, pairKey, pair);
        }
        int required = (source == null ? 1 : 0) + (pair == null ? 1 : 0);
        if (entries.size() + required > maximumEntries) return ticket(Status.CAPACITY, null, null);
        if (source == null) source = insert(sourceKey, now, ttl, deadline);
        source.attempts++;
        if (pair == null) pair = insert(pairKey, now, ttl, deadline);
        return ticket(pair.failures >= policy.pairFailures() ? Status.PAIR_FAILURES : Status.PASS,
                      pairKey, pair);
    }

    private Entry insert(String key, long now, long ttl, long deadline) {
        Entry entry = new Entry(key, now, ttl, deadline);
        entries.put(key, entry);
        expiryIndex.add(entry);
        return entry;
    }
    private Entry live(String key, long now) {
        Entry entry = entries.get(key);
        if (entry != null) {
            expiryInspections++;
            if (entry.expired(now)) { removeExpired(entry); return null; }
        }
        return entry;
    }
    private void pruneExpired(long now) {
        for (int i = 0; i < EXPIRY_BUDGET && !expiryIndex.isEmpty(); i++) {
            Entry oldest = expiryIndex.first();
            expiryInspections++;
            if (!oldest.expired(now)) return;
            removeExpired(oldest);
        }
    }
    private void removeExpired(Entry entry) {
        entries.remove(entry.key);
        expiryIndex.remove(entry);
        expiredEntries++;
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
    /** Number of retained entries; expired entries are incrementally removed on later admissions. */
    public synchronized int size() { return entries.size(); }
    public synchronized Maintenance maintenance() {
        return new Maintenance(expiryInspections, expiredEntries, entries.size(), expiryIndex.size());
    }
}
