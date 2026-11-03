package dev.gatekeeper;

import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/** Small repeatable admission-only harness; not a password throughput or capacity claim. */
final class AdmissionBenchmarks {
    static void measure(Gatekeeper gate,String store) throws Exception {
        int warmup=100,count=2000,threads=4;
        for(int i=0;i<warmup;i++)try(var a=gate.admit(GatekeeperTest.IP,"benchmark")){a.complete(Gatekeeper.Outcome.SUCCESS);}
        long[] latencies=new long[count];
        try(var pool=Executors.newFixedThreadPool(threads)){
            var futures=new ArrayList<Future<?>>();
            for(int i=0;i<count;i++){int index=i;futures.add(pool.submit(()->{
                long start=System.nanoTime();
                try(var a=gate.admit(GatekeeperTest.IP,"benchmark")){
                    latencies[index]=System.nanoTime()-start;
                    if(!a.allowed())throw new AssertionError("Unexpected benchmark denial: "+a.reason());
                    a.complete(Gatekeeper.Outcome.SUCCESS);
                }
            }));}
            for(var f:futures)f.get(15,TimeUnit.SECONDS);
        }
        Arrays.sort(latencies);
        String json="{\n  \"store\":\""+store+"\",\n  \"java\":\""+System.getProperty("java.version")
            +"\",\n  \"threads\":"+threads+",\n  \"warmup\":"+warmup+",\n  \"samples\":"+count
            +",\n  \"scope\":\"admit call only; no password work; one source/account; local machine\",\n  \"p50_us\":"+latencies[count/2]/1000.0
            +",\n  \"p95_us\":"+latencies[(int)(count*.95)-1]/1000.0+",\n  \"p99_us\":"+latencies[(int)(count*.99)-1]/1000.0+"\n}\n";
        Files.writeString(Path.of("target","benchmark-"+store+".json"),json);
    }
}
