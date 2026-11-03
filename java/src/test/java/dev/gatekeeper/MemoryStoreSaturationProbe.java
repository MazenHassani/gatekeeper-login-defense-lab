package dev.gatekeeper;

import dev.gatekeeper.*;
import java.time.Duration;
import java.util.Arrays;
public final class MemoryStoreSaturationProbe {
 public static void main(String[] ignored) {
  Policy policy=new Policy(1_000_000,10,Duration.ofHours(1),1,Policy.Mode.ENFORCE);
  for(int capacity:new int[]{10_000,100_000,1_000_000}) {
   BoundedMemoryStore store=new BoundedMemoryStore(capacity);
   for(int i=0;i<capacity/2;i++) store.inspectAndRecord("s:"+i,"p:"+i,0,policy);
   long[] latency=new long[200];
   for(int i=0;i<latency.length;i++) {
    long start=System.nanoTime();
    if(store.inspectAndRecord("new-s:"+i,"new-p:"+i,0,policy).status()!=AdmissionStore.Status.CAPACITY)throw new AssertionError();
    latency[i]=System.nanoTime()-start;
   }
   Arrays.sort(latency);
   System.out.printf("capacity=%d samples=200 p50_us=%.3f p95_us=%.3f p99_us=%.3f%n",capacity,latency[100]/1000.0,latency[189]/1000.0,latency[197]/1000.0);
  }
 }
}
