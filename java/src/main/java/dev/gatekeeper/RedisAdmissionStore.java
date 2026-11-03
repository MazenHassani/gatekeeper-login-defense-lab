package dev.gatekeeper;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import redis.clients.jedis.RedisClient;

/**
 * Experimental shared Redis policy state, tested against standalone Redis only.
 * Caller owns a dedicated, timeout/pool-bounded RedisClient and its lifecycle.
 * No automatic retries, fallback, or distributed password-work semaphore.
 */
public final class RedisAdmissionStore implements AdmissionStore {
    private static final String INSPECT = """
        local signature = redis.call('HGET', KEYS[1], '__policy')
        if signature and signature ~= ARGV[6] then return redis.error_reply('Gatekeeper policy mismatch') end
        local t = redis.call('TIME')
        local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
        local stale = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', now, 'LIMIT', 0, 32)
        for _,field in ipairs(stale) do
          redis.call('HDEL', KEYS[1], field)
          redis.call('ZREM', KEYS[2], field)
        end
        local function live(field)
          local expiry = redis.call('ZSCORE', KEYS[2], field)
          if expiry and tonumber(expiry) <= now then
            redis.call('HDEL', KEYS[1], field)
            redis.call('ZREM', KEYS[2], field)
            return nil
          end
          return expiry
        end
        local sourceExpiry = live(ARGV[1])
        local pairExpiry = live(ARGV[2])
        local sourceCount = tonumber(redis.call('HGET', KEYS[1], ARGV[1]) or '0')
        if sourceExpiry and sourceCount >= tonumber(ARGV[3]) then return {1, pairExpiry or '0'} end
        local required = (sourceExpiry and 0 or 1) + (pairExpiry and 0 or 1)
        if redis.call('ZCARD', KEYS[2]) + required > tonumber(ARGV[5]) then return {3, '0'} end
        redis.call('HSET', KEYS[1], '__policy', ARGV[6])
        if not sourceExpiry then
          sourceExpiry = now + tonumber(ARGV[4])
          redis.call('ZADD', KEYS[2], sourceExpiry, ARGV[1])
          redis.call('HSET', KEYS[1], ARGV[1], 0)
        end
        redis.call('HINCRBY', KEYS[1], ARGV[1], 1)
        if not pairExpiry then
          pairExpiry = now + tonumber(ARGV[4])
          redis.call('ZADD', KEYS[2], pairExpiry, ARGV[2])
          redis.call('HSET', KEYS[1], ARGV[2], 0)
        end
        redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[4]) * 2)
        redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[4]) * 2)
        local failures = tonumber(redis.call('HGET', KEYS[1], ARGV[2]) or '0')
        if failures >= tonumber(ARGV[7]) then return {2, tostring(pairExpiry)} end
        return {0, tostring(pairExpiry)}
        """;
    private static final String FAILURE = """
        local expiry = redis.call('ZSCORE', KEYS[2], ARGV[1])
        local t = redis.call('TIME')
        local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
        if expiry and tonumber(expiry) == tonumber(ARGV[2]) and tonumber(expiry) > now then
          local count = tonumber(redis.call('HGET', KEYS[1], ARGV[1]) or '0')
          if count < tonumber(ARGV[3]) then redis.call('HINCRBY', KEYS[1], ARGV[1], 1) end
        end
        return 1
        """;
    private final RedisClient client;
    private final String namespace;
    private final int perShardCapacity;

    /** Up to 16 source-selected state shards, at most capacity entries per shard plus policy metadata. */
    public RedisAdmissionStore(RedisClient client, String namespace, int perShardCapacity) {
        this.client = Objects.requireNonNull(client);
        if (namespace == null || !namespace.matches("[A-Za-z0-9_-]{1,32}")
                || perShardCapacity < 2 || perShardCapacity > 100_000) {
            throw new IllegalArgumentException("Bounded namespace and capacity 2..100000 required");
        }
        this.namespace = namespace;
        this.perShardCapacity = perShardCapacity;
    }
    @Override public boolean requiresSharedIdentity() { return true; }
    @Override public Ticket inspectAndRecord(String sourceKey, String pairKey, long ignoredTime, Policy policy) {
        if (sourceKey == null || !sourceKey.matches("s:[0-9a-f]{64}")
                || pairKey == null || !pairKey.matches("p:[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Gatekeeper digest keys required");
        }
        String tag = "gk:{" + namespace + "-" + sourceKey.charAt(2) + "}";
        List<String> keys = List.of(tag + ":counts", tag + ":expiry");
        String signature = policy.sourceAttempts() + ":" + policy.pairFailures() + ":"
                + policy.window().toMillis() + ":" + perShardCapacity;
        Object response = client.eval(INSPECT, keys, List.of(sourceKey, pairKey,
                String.valueOf(policy.sourceAttempts()), String.valueOf(policy.window().toMillis()),
                String.valueOf(perShardCapacity), signature, String.valueOf(policy.pairFailures())));
        List<?> values = (List<?>) response;
        int status = ((Number) values.get(0)).intValue();
        String generation = values.get(1).toString();
        Status result = switch (status) {
            case 0 -> Status.PASS;
            case 1 -> Status.SOURCE_RATE;
            case 2 -> Status.PAIR_FAILURES;
            case 3 -> Status.CAPACITY;
            default -> throw new IllegalStateException("Unknown Redis admission result");
        };
        return new Ticket() {
            private final AtomicBoolean recorded = new AtomicBoolean();
            @Override public Status status() { return result; }
            @Override public void credentialFailed(long ignored) {
                if (result == Status.CAPACITY || !recorded.compareAndSet(false, true)) return;
                client.eval(FAILURE, keys, List.of(pairKey, generation, String.valueOf(policy.pairFailures())));
            }
        };
    }
}
