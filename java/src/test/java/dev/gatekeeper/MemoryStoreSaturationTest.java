package dev.gatekeeper;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;

class MemoryStoreSaturationTest {
    private final Policy policy = new Policy(1_000_000, 10, Duration.ofHours(1), 8, Policy.Mode.ENFORCE);
    private BoundedMemoryStore filled(int capacity, long now) {
        var store = new BoundedMemoryStore(capacity);
        for (int i = 0; i < capacity / 2; i++) store.inspectAndRecord("s:" + i, "p:" + i, now, policy);
        return store;
    }
    @Test void attackerChurnAtFullCapacityHasBoundedExpiryWork() throws Exception {
        int capacity = 100_000, samples = 1_000;
        var store = filled(capacity, 0);
        var before = store.maintenance();
        long[] timings = new long[samples];
        for (int i = 0; i < samples; i++) {
            long start = System.nanoTime();
            assertEquals(AdmissionStore.Status.CAPACITY, store.inspectAndRecord("new-s:" + i, "new-p:" + i, 0, policy).status());
            timings[i] = System.nanoTime() - start;
        }
        var after = store.maintenance();
        // Operational invariant, independent of wall-clock/JIT noise: no capacity-sized scan.
        assertTrue(after.expiryInspections() - before.expiryInspections() <= 34L * samples);
        assertEquals(0, after.expiredEntries());
        assertEquals(capacity, after.retainedEntries());
        assertEquals(after.retainedEntries(), after.expiryIndexEntries());
        Arrays.sort(timings);
        Files.writeString(Path.of("target", "memory-saturation.json"),
            "{\"capacity\":" + capacity + ",\"denied_churn_samples\":" + samples
            + ",\"expiry_inspections\":" + (after.expiryInspections() - before.expiryInspections())
            + ",\"p50_us\":" + timings[samples / 2] / 1000.0 + ",\"p95_us\":" + timings[949] / 1000.0
            + ",\"p99_us\":" + timings[989] / 1000.0 + "}\n");
    }
    @Test void massExpiryAndTargetedReplacementKeepIndexAndPerRequestWorkBounded() {
        var store = filled(10_000, 0);
        long expired = policy.window().toNanos();
        for (int i = 0; i < 400; i++) {
            var before = store.maintenance();
            assertEquals(AdmissionStore.Status.PASS,
                store.inspectAndRecord("s:4999", "p:4999", expired + i, policy).status());
            var after = store.maintenance();
            assertTrue(after.expiryInspections() - before.expiryInspections() <= 34);
            assertTrue(after.expiredEntries() - before.expiredEntries() <= 34);
            assertEquals(after.retainedEntries(), after.expiryIndexEntries());
            assertTrue(after.retainedEntries() <= 10_000);
        }
        assertEquals(2, store.size());
    }
    @Test void concurrentChurnDoesNotEvictLiveFailedHistory() throws Exception {
        var store = filled(10_000, 0);
        for (int i = 0; i < 10; i++) {
            // Real failed checks each have a distinct ticket.
            store.inspectAndRecord("s:0", "p:0", 0, policy).credentialFailed(0);
        }
        try (var pool = Executors.newFixedThreadPool(8)) {
            var futures = new java.util.ArrayList<Future<?>>();
            for (int i = 0; i < 1_000; i++) {
                int index = i;
                futures.add(pool.submit(() -> assertEquals(AdmissionStore.Status.CAPACITY,
                    store.inspectAndRecord("churn-s:" + index, "churn-p:" + index, 0, policy).status())));
            }
            for (var future : futures) future.get(5, TimeUnit.SECONDS);
        }
        assertEquals(AdmissionStore.Status.PAIR_FAILURES, store.inspectAndRecord("s:0", "p:0", 0, policy).status());
        assertEquals(10_000, store.size());
        assertEquals(store.size(), store.maintenance().expiryIndexEntries());
    }
    @Test void monotonicNanoTimeRolloverPreservesExpiryOrdering() {
        var store = new BoundedMemoryStore(10);
        var shortPolicy = new Policy(10, 1, Duration.ofMillis(1), 1, Policy.Mode.ENFORCE);
        long nearWrap = Long.MAX_VALUE - 100;
        store.inspectAndRecord("s", "p", nearWrap, shortPolicy).credentialFailed(nearWrap);
        assertEquals(AdmissionStore.Status.PASS, store.inspectAndRecord("s", "p", nearWrap + 1_000_000, shortPolicy).status());
        assertEquals(store.size(), store.maintenance().expiryIndexEntries());
    }
    @Test void outOfOrderConcurrentClockSamplesDoNotRejectOrMisorderExpiry() {
        var store = new BoundedMemoryStore(10);
        var shortPolicy = new Policy(100, 1, Duration.ofMillis(100), 1, Policy.Mode.ENFORCE);
        long laterSample = Duration.ofMillis(10).toNanos();
        store.inspectAndRecord("later-source", "later-pair", laterSample, shortPolicy).credentialFailed(laterSample);
        // Sampled earlier by another thread, but delivered after the first synchronized call.
        store.inspectAndRecord("earlier-source", "earlier-pair", 0, shortPolicy).credentialFailed(0);
        long earlierExpiry = Duration.ofMillis(100).toNanos();
        assertEquals(AdmissionStore.Status.PAIR_FAILURES,
            store.inspectAndRecord("later-source", "later-pair", earlierExpiry, shortPolicy).status());
        assertEquals(AdmissionStore.Status.PASS,
            store.inspectAndRecord("earlier-source", "earlier-pair", earlierExpiry, shortPolicy).status());
        assertEquals(store.size(), store.maintenance().expiryIndexEntries());
    }

}
