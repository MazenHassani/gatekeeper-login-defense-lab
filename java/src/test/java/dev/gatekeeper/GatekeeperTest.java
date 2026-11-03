package dev.gatekeeper;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;

class GatekeeperTest {
    static final java.net.InetAddress IP = ClientAddress.literal("192.0.2.1");
    static Policy policy(int rate, int failures, int budget, Policy.Mode mode) {
        return new Policy(rate, failures, Duration.ofSeconds(10), budget, mode);
    }
    @Test void outcomesAndPairFailures() {
        Gatekeeper gate = new Gatekeeper(policy(100,2,2,Policy.Mode.ENFORCE),new BoundedMemoryStore(100));
        for(int i=0;i<2;i++) try(var a=gate.admit(IP,"alice")){assertTrue(a.allowed());a.complete(Gatekeeper.Outcome.INVALID_CREDENTIALS);}
        assertEquals(Gatekeeper.Reason.PAIR_FAILURES,gate.admit(IP,"alice").reason());
        try(var a=gate.admit(IP,"bob")){assertTrue(a.allowed());a.complete(Gatekeeper.Outcome.SUCCESS);}
        assertEquals(0,gate.metrics().inFlight());
    }
    @Test void sourceRateAndExpiry() {
        AtomicLong clock=new AtomicLong(0);
        Gatekeeper gate=new Gatekeeper(policy(2,10,1,Policy.Mode.ENFORCE),new BoundedMemoryStore(100),clock::get);
        for(int i=0;i<2;i++)try(var a=gate.admit(IP,"a")){assertTrue(a.allowed());}
        assertEquals(Gatekeeper.Reason.SOURCE_RATE,gate.admit(IP,"another").reason());
        clock.set(Duration.ofSeconds(10).toNanos());
        try(var a=gate.admit(IP,"a")){assertTrue(a.allowed());}
    }
    @Test void capacityDoesNotEvictLiveState() {
        BoundedMemoryStore store=new BoundedMemoryStore(2);
        Gatekeeper gate=new Gatekeeper(policy(100,1,1,Policy.Mode.ENFORCE),store);
        try(var a=gate.admit(IP,"a")){a.complete(Gatekeeper.Outcome.INVALID_CREDENTIALS);}
        assertEquals(Gatekeeper.Reason.STORE_CAPACITY,gate.admit(IP,"b").reason());
        assertEquals(Gatekeeper.Reason.PAIR_FAILURES,gate.admit(IP,"a").reason());
        assertEquals(2,store.size());
    }
    @Test void shadowBypassesOnlyPolicy() {
        Gatekeeper gate=new Gatekeeper(policy(1,1,1,Policy.Mode.SHADOW),new BoundedMemoryStore(10));
        var first=gate.admit(IP,"a");
        assertEquals(Gatekeeper.Reason.BUSY,gate.admit(IP,"a").reason());
        first.close();
        try(var a=gate.admit(IP,"a")){assertTrue(a.allowed());assertEquals(Gatekeeper.Reason.SOURCE_RATE,a.observedReason());}
        assertEquals(2,gate.metrics().wouldDeny());
    }
    @Test void errorAndIdempotentRelease() {
        Gatekeeper gate=new Gatekeeper(policy(10,1,1,Policy.Mode.ENFORCE),new BoundedMemoryStore(10));
        var a=gate.admit(IP,"a");a.close();a.close();a.complete(Gatekeeper.Outcome.SUCCESS);
        assertEquals(1,gate.metrics().errors());assertEquals(0,gate.metrics().successes());
        try(var b=gate.admit(IP,"a")){assertTrue(b.allowed());}
        assertEquals(0,gate.metrics().inFlight());
    }
    @Test void failureFromExpiredTicketCannotPoisonNewWindow() {
        AtomicLong clock=new AtomicLong(0);
        Gatekeeper gate=new Gatekeeper(policy(100,1,2,Policy.Mode.ENFORCE),new BoundedMemoryStore(10),clock::get);
        var old=gate.admit(IP,"a");clock.set(Duration.ofSeconds(11).toNanos());
        try(var current=gate.admit(IP,"a")){old.complete(Gatekeeper.Outcome.INVALID_CREDENTIALS);}
        try(var next=gate.admit(IP,"a")){assertTrue(next.allowed());}
    }
    @Test void sharedNatFalsePositiveIsVisible() {
        Gatekeeper gate=new Gatekeeper(policy(2,100,1,Policy.Mode.ENFORCE),new BoundedMemoryStore(10));
        try(var a=gate.admit(IP,"bot1")){}try(var a=gate.admit(IP,"bot2")){}
        assertEquals(Gatekeeper.Reason.SOURCE_RATE,gate.admit(IP,"legitimate").reason());
        assertEquals(1,gate.metrics().policyDenied());
    }
    @Test void storeOutageFailsClosedEvenInShadow() {
        AdmissionStore failing=(s,p,t,c)->{throw new IllegalStateException("outage");};
        Gatekeeper gate=new Gatekeeper(policy(100,1,1,Policy.Mode.SHADOW),failing);
        assertEquals(Gatekeeper.Reason.STORE_ERROR,gate.admit(IP,"a").reason());
        assertEquals(0,gate.metrics().inFlight());
    }
    @Test void outcomeStoreFailureStillReleases() {
        AdmissionStore failing=(s,p,t,c)->new AdmissionStore.Ticket(){
            public AdmissionStore.Status status(){return AdmissionStore.Status.PASS;}
            public void credentialFailed(long now){throw new IllegalStateException("outage");}};
        Gatekeeper gate=new Gatekeeper(policy(100,1,1,Policy.Mode.ENFORCE),failing);
        try(var a=gate.admit(IP,"a")){a.complete(Gatekeeper.Outcome.INVALID_CREDENTIALS);}
        assertEquals(0,gate.metrics().inFlight());assertEquals(1,gate.metrics().storeErrors());
    }
    @Test void concurrentBudgetNeverOversubscribes() throws Exception {
        Gatekeeper gate=new Gatekeeper(policy(10000,10000,3,Policy.Mode.ENFORCE),new BoundedMemoryStore(100));
        AtomicInteger active=new AtomicInteger(),peak=new AtomicInteger();
        CountDownLatch started=new CountDownLatch(3),release=new CountDownLatch(1);
        try(var executor=Executors.newFixedThreadPool(24)){
            var tasks=new java.util.ArrayList<Future<?>>();
            for(int i=0;i<120;i++)tasks.add(executor.submit(()->{
                try(var a=gate.admit(IP,"a")){
                    if(a.allowed()){
                        int current=active.incrementAndGet();peak.accumulateAndGet(current,Math::max);started.countDown();
                        try{release.await(5,TimeUnit.SECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();}
                        finally{active.decrementAndGet();}
                    }
                }
            }));
            assertTrue(started.await(5,TimeUnit.SECONDS));assertEquals(3,gate.metrics().inFlight());
            release.countDown();for(var task:tasks)task.get(5,TimeUnit.SECONDS);
        }
        assertTrue(peak.get()<=3);assertEquals(0,gate.metrics().inFlight());
    }
    @Test void concurrentSourceLimitIsAtomic() throws Exception {
        Gatekeeper gate=new Gatekeeper(policy(7,1000,100,Policy.Mode.ENFORCE),new BoundedMemoryStore(100));
        AtomicInteger passes=new AtomicInteger();
        try(var executor=Executors.newFixedThreadPool(20)){
            var futures=new java.util.ArrayList<Future<?>>();
            for(int i=0;i<100;i++)futures.add(executor.submit(()->{try(var a=gate.admit(IP,"a")){if(a.allowed())passes.incrementAndGet();}}));
            for(var f:futures)f.get();
        }
        assertEquals(7,passes.get());
    }
    @Test void noRawIdentityKeysOrHighCardinalityMetrics() {
        java.util.List<String> keys=new java.util.ArrayList<>();
        AdmissionStore inspecting=(s,p,t,c)->{keys.add(s);keys.add(p);return new AdmissionStore.Ticket(){
            public AdmissionStore.Status status(){return AdmissionStore.Status.PASS;} public void credentialFailed(long n){}};};
        Gatekeeper gate=new Gatekeeper(policy(10,1,1,Policy.Mode.ENFORCE),inspecting);
        try(var a=gate.admit(IP,"alice@example.invalid")){}
        assertEquals(2,keys.size());assertTrue(keys.stream().allMatch(k->k.length()==66));
        assertFalse(keys.toString().contains("alice"));assertFalse(gate.metrics().toString().contains("192.0.2"));
    }
    @Test void invalidInputsNeverReachStore() {
        AdmissionStore bad=(s,p,t,c)->{fail("store called");return null;};
        Gatekeeper gate=new Gatekeeper(policy(10,1,1,Policy.Mode.ENFORCE),bad);
        assertFalse(gate.admit(IP,"x".repeat(257)).allowed());assertFalse(gate.admit(null,"a").allowed());
    }
    @Test void proxyTrustAndSpoofing() {
        var proxy=ClientAddress.literal("10.0.0.1");var second=ClientAddress.literal("10.0.0.2");
        assertEquals(IP,ClientAddress.resolve(IP,"spoof.invalid",Set.of(proxy)));
        assertEquals(IP,ClientAddress.resolve(proxy,"198.51.100.9,192.0.2.1,10.0.0.2",Set.of(proxy,second)));
        assertEquals(proxy,ClientAddress.resolve(proxy,null,Set.of(proxy)));
        assertThrows(IllegalArgumentException.class,()->ClientAddress.resolve(proxy,"client.invalid",Set.of(proxy)));
        assertThrows(IllegalArgumentException.class,()->ClientAddress.literal("127.1"));
        assertThrows(IllegalArgumentException.class,()->ClientAddress.literal("012.0.0.1"));
        assertThrows(IllegalArgumentException.class,()->ClientAddress.literal("fe80::1%eth0"));
        assertEquals(ClientAddress.literal("::1"),ClientAddress.literal("0:0:0:0:0:0:0:1"));
    }
    @Test void cancellationReleasesOnlyAfterWorkStops() throws Exception {
        var gate=new Gatekeeper(policy(100,10,1,Policy.Mode.ENFORCE),new BoundedMemoryStore(100));
        var running=new CountDownLatch(1);var stopped=new CountDownLatch(1);
        try(var executor=Executors.newSingleThreadExecutor()){
            var task=executor.submit(()->{
                try(var a=gate.admit(IP,"a")){
                    running.countDown();
                    try{new CountDownLatch(1).await();}catch(InterruptedException e){Thread.currentThread().interrupt();}
                }finally{stopped.countDown();}
            });
            assertTrue(running.await(2,TimeUnit.SECONDS));assertEquals(1,gate.metrics().inFlight());
            task.cancel(true);assertTrue(stopped.await(2,TimeUnit.SECONDS));
            assertEquals(0,gate.metrics().inFlight());
        }
    }
    @Test void closedAttemptCannotBeReusedAsAnActivePermit() {
        var gate=new Gatekeeper(policy(100,10,1,Policy.Mode.ENFORCE),new BoundedMemoryStore(100));
        var attempt=gate.admit(IP,"a");assertTrue(attempt.allowed());attempt.close();assertFalse(attempt.allowed());
    }

}
