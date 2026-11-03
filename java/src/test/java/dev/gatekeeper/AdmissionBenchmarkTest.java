package dev.gatekeeper;
import org.junit.jupiter.api.Test;
class AdmissionBenchmarkTest {
    @Test void localAdmissionMeasurements() throws Exception {
        var gate=new Gatekeeper(GatekeeperTest.policy(100000,100000,8,Policy.Mode.ENFORCE),new BoundedMemoryStore(1000));
        AdmissionBenchmarks.measure(gate,"memory");
    }
}
