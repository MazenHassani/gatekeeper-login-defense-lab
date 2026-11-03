package dev.gatekeeper;

import java.time.Duration;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import redis.clients.jedis.Connection;
import redis.clients.jedis.DefaultJedisClientConfig;
import redis.clients.jedis.RedisClient;

/** Local test/example factory. Production credentials/TLS/topology require application-owned client setup. */
public final class RedisClients {
    private RedisClients() {}
    /** Only connects to loopback, has a bounded fail-fast pool and 200 ms connect/read timeouts. */
    public static RedisClient loopback(int port) {
        GenericObjectPoolConfig<Connection> pool = new GenericObjectPoolConfig<>();
        pool.setMaxTotal(8); pool.setMaxIdle(8); pool.setMinIdle(0);
        pool.setBlockWhenExhausted(false); pool.setMaxWait(Duration.ofMillis(200));
        return RedisClient.builder().hostAndPort("127.0.0.1", port).poolConfig(pool)
                .clientConfig(DefaultJedisClientConfig.builder().connectionTimeoutMillis(200)
                        .socketTimeoutMillis(200).build()).build();
    }
}
