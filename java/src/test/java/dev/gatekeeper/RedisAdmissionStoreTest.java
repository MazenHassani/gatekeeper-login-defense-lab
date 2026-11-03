package dev.gatekeeper;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.*;
import redis.clients.jedis.RedisClient;

class RedisAdmissionStoreTest {
    static Process server;
    static int port;
    static Path temp;
    static RedisClient client;
    static String namespace(){return "test"+UUID.randomUUID().toString().replace("-","").substring(0,12);}
    @BeforeAll static void start() throws Exception {
        try(var socket=new ServerSocket(0,1,InetAddress.getLoopbackAddress())){port=socket.getLocalPort();}
        temp=Files.createTempDirectory("gatekeeper-redis-");
        server=new ProcessBuilder("redis-server","--bind","127.0.0.1","--port",String.valueOf(port),
                "--save","","--appendonly","no","--dir",temp.toString(),"--maxmemory","64mb",
                "--maxmemory-policy","noeviction").redirectErrorStream(true).redirectOutput(temp.resolve("redis.log").toFile()).start();
        client=RedisClients.loopback(port);
        long deadline=System.nanoTime()+Duration.ofSeconds(5).toNanos();
        while(true){try{assertEquals("PONG",client.ping());break;}catch(RuntimeException e){
            if(System.nanoTime()>deadline)throw e;Thread.sleep(20);
        }}
    }
    @AfterAll static void stop() throws Exception {
        if(client!=null)client.close();
        if(server!=null){server.destroy();if(!server.waitFor(3,TimeUnit.SECONDS))server.destroyForcibly();}
    }
    static Gatekeeper gate(String ns,int rate,int failures,int capacity){
        return new Gatekeeper(GatekeeperTest.policy(rate,failures,100,Policy.Mode.ENFORCE),
                new RedisAdmissionStore(client,ns,capacity),new byte[32]);
    }
    @Test void twoInstancesShareOutcomeStateAndKeysArePseudonymous(){
        String ns=namespace();var one=gate(ns,100,2,100);var two=gate(ns,100,2,100);
        try(var a=one.admit(GatekeeperTest.IP,"alice")){a.complete(Gatekeeper.Outcome.INVALID_CREDENTIALS);}
        try(var a=two.admit(GatekeeperTest.IP,"alice")){a.complete(Gatekeeper.Outcome.INVALID_CREDENTIALS);}
        assertEquals(Gatekeeper.Reason.PAIR_FAILURES,one.admit(GatekeeperTest.IP,"alice").reason());
        // KEYS is used only in a dedicated temporary integration-test server, never runtime code.
        for(String key:client.keys("gk:{"+ns+"-*"))for(String field:client.type(key).equals("hash")?client.hkeys(key):client.zrange(key,0,-1)){
            assertFalse(field.contains("alice"));assertFalse(field.contains("192.0.2"));
        }
    }
    @Test void capacityNoEvictionAndPolicyMismatch(){
        String ns=namespace();var one=gate(ns,100,1,2);
        try(var a=one.admit(GatekeeperTest.IP,"a")){a.complete(Gatekeeper.Outcome.INVALID_CREDENTIALS);}
        assertEquals(Gatekeeper.Reason.STORE_CAPACITY,one.admit(GatekeeperTest.IP,"new-account").reason());
        assertEquals(Gatekeeper.Reason.PAIR_FAILURES,one.admit(GatekeeperTest.IP,"a").reason());
        var mismatched=gate(ns,99,1,2);
        assertEquals(Gatekeeper.Reason.STORE_ERROR,mismatched.admit(GatekeeperTest.IP,"a").reason());
    }
    @Test void concurrentAtomicRateAcrossInstances() throws Exception {
        String ns=namespace();var one=gate(ns,7,1000,100);var two=gate(ns,7,1000,100);
        AtomicInteger allowed=new AtomicInteger();
        try(var pool=Executors.newFixedThreadPool(6)){
            var tasks=new ArrayList<Future<?>>();
            for(int i=0;i<100;i++){var selected=i%2==0?one:two;tasks.add(pool.submit(()->{try(var a=selected.admit(GatekeeperTest.IP,"a")){if(a.allowed())allowed.incrementAndGet();}}));}
            for(var task:tasks)task.get(5,TimeUnit.SECONDS);
        }
        assertEquals(7,allowed.get());
    }
    @Test void actualSeparateJvmsCoordinateRate() throws Exception {
        String ns=namespace();String cp=System.getProperty("surefire.test.class.path",System.getProperty("java.class.path"));
        List<String> cmd=List.of(Path.of(System.getProperty("java.home"),"bin","java").toString(),"-cp",cp,
                "dev.gatekeeper.RedisWorker",String.valueOf(port),ns);
        Process one=new ProcessBuilder(cmd).redirectErrorStream(true).start();
        Process two=new ProcessBuilder(cmd).redirectErrorStream(true).start();
        assertTrue(one.waitFor(15,TimeUnit.SECONDS));assertTrue(two.waitFor(15,TimeUnit.SECONDS));
        String a=new String(one.getInputStream().readAllBytes()),b=new String(two.getInputStream().readAllBytes());
        assertEquals(0,one.exitValue(),a);assertEquals(0,two.exitValue(),b);
        int total=0;for(String line:(a+"\n"+b).split("\n"))if(line.startsWith("ADMITTED="))total+=Integer.parseInt(line.substring(9).trim());
        assertEquals(30,total);
    }
    @Test void expiredReceiptCannotPoisonNextGeneration() throws Exception {
        String ns=namespace();var policy=new Policy(100,1,Duration.ofMillis(100),2,Policy.Mode.ENFORCE);
        var gate=new Gatekeeper(policy,new RedisAdmissionStore(client,ns,100),new byte[32]);
        var old=gate.admit(GatekeeperTest.IP,"a");Thread.sleep(150);
        try(var current=gate.admit(GatekeeperTest.IP,"a")){assertTrue(current.allowed());old.complete(Gatekeeper.Outcome.INVALID_CREDENTIALS);}
        try(var next=gate.admit(GatekeeperTest.IP,"a")){assertTrue(next.allowed());}
    }
    @Test void unavailableRedisFailsClosedWithinBound() throws Exception {
        int unused;try(var socket=new ServerSocket(0,1,InetAddress.getLoopbackAddress())){unused=socket.getLocalPort();}
        try(var unavailable=RedisClients.loopback(unused)){
            var gate=new Gatekeeper(GatekeeperTest.policy(100,1,1,Policy.Mode.SHADOW),new RedisAdmissionStore(unavailable,namespace(),10),new byte[32]);
            long start=System.nanoTime();
            assertEquals(Gatekeeper.Reason.STORE_ERROR,gate.admit(GatekeeperTest.IP,"a").reason());
            assertTrue(System.nanoTime()-start<Duration.ofSeconds(2).toNanos());
            assertEquals(0,gate.metrics().inFlight());
        }
    }
    @Test void sharedBackendRejectsAccidentalRandomIdentity() {
        assertThrows(IllegalArgumentException.class,()->new Gatekeeper(
            GatekeeperTest.policy(10,1,1,Policy.Mode.ENFORCE),new RedisAdmissionStore(client,namespace(),100)));
    }
    @Test void timeoutIsNotRetriedAndExistingBudgetRemainsHeld() throws Exception {
        String ns=namespace();
        var gate=new Gatekeeper(GatekeeperTest.policy(100,10,2,Policy.Mode.ENFORCE),
            new RedisAdmissionStore(client,ns,100),new byte[32]);
        var held=gate.admit(GatekeeperTest.IP,"a"); assertTrue(held.allowed());
        try(var control=new redis.clients.jedis.Jedis("127.0.0.1",port)){control.clientPause(450);}
        long start=System.nanoTime();
        assertEquals(Gatekeeper.Reason.STORE_ERROR,gate.admit(GatekeeperTest.IP,"a").reason());
        assertTrue(System.nanoTime()-start<Duration.ofSeconds(2).toNanos());
        assertEquals(1,gate.metrics().inFlight());
        Thread.sleep(550);
        // The timed-out mutation may or may not have executed. Either is valid; no blind retry.
        for(String key:client.keys("gk:{"+ns+"-*:counts"))
            for(var entry:client.hgetAll(key).entrySet()) if(entry.getKey().startsWith("s:"))
                assertTrue(Integer.parseInt(entry.getValue())<=2);
        held.close();assertEquals(0,gate.metrics().inFlight());
        try(var next=gate.admit(GatekeeperTest.IP,"a")){assertTrue(next.allowed());}
    }
    @Test void exhaustedConnectionPoolDeniesPromptly() {
        var resources=new ArrayList<redis.clients.jedis.Connection>();
        try {
            for(int i=0;i<8;i++)resources.add(client.getPool().getResource());
            var gate=gate(namespace(),100,1,100);
            long start=System.nanoTime();
            assertEquals(Gatekeeper.Reason.STORE_ERROR,gate.admit(GatekeeperTest.IP,"a").reason());
            assertTrue(System.nanoTime()-start<Duration.ofSeconds(1).toNanos());
        } finally {resources.forEach(redis.clients.jedis.Connection::close);}
    }
    @Test void redisOutOfMemoryDoesNotAdmit() {
        // Only the isolated test-owned server is modified, then restored.
        client.configSet("maxmemory","1");
        try {
            var gate=gate(namespace(),100,1,100);
            assertEquals(Gatekeeper.Reason.STORE_ERROR,gate.admit(GatekeeperTest.IP,"a").reason());
        } finally {client.configSet("maxmemory","67108864");}
    }

    @Test void redisAdmissionMeasurements() throws Exception {
        AdmissionBenchmarks.measure(gate(namespace(),100000,100000,1000),"redis");
    }

    @Test void restartLosesHistoryAndRequiresOperationalRecovery() throws Exception {
        String ns=namespace();var before=gate(ns,100,1,100);
        try(var a=before.admit(GatekeeperTest.IP,"a")){a.complete(Gatekeeper.Outcome.INVALID_CREDENTIALS);}
        assertEquals(Gatekeeper.Reason.PAIR_FAILURES,before.admit(GatekeeperTest.IP,"a").reason());
        var held=before.admit(GatekeeperTest.IP,"other");assertTrue(held.allowed());
        server.destroy();assertTrue(server.waitFor(3,TimeUnit.SECONDS));
        assertEquals(Gatekeeper.Reason.STORE_ERROR,before.admit(GatekeeperTest.IP,"a").reason());
        assertEquals(1,before.metrics().inFlight());held.close();assertEquals(0,before.metrics().inFlight());
        client.close();
        server=new ProcessBuilder("redis-server","--bind","127.0.0.1","--port",String.valueOf(port),
            "--save","","--appendonly","no","--dir",temp.toString(),"--maxmemory","64mb",
            "--maxmemory-policy","noeviction").redirectErrorStream(true).redirectOutput(temp.resolve("restarted.log").toFile()).start();
        client=RedisClients.loopback(port);
        long deadline=System.nanoTime()+Duration.ofSeconds(5).toNanos();
        while(true){try{client.ping();break;}catch(RuntimeException e){if(System.nanoTime()>deadline)throw e;Thread.sleep(20);}}
        var after=gate(ns,100,1,100);
        // Demonstrates the documented limitation: a nonpersistent restart erased previous failed history.
        try(var a=after.admit(GatekeeperTest.IP,"a")){assertTrue(a.allowed());}
    }

}
