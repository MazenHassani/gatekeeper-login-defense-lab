package dev.gatekeeper;

/** Separate JVM integration-test worker; loopback-only Redis with synthetic identities. */
public final class RedisWorker {
    public static void main(String[] args) {
        try(var client=RedisClients.loopback(Integer.parseInt(args[0]))) {
            var store=new RedisAdmissionStore(client,args[1],100);
            var gate=new Gatekeeper(GatekeeperTest.policy(30,1000,1,Policy.Mode.ENFORCE),store,new byte[32]);
            int count=0;
            for(int i=0;i<100;i++)try(var a=gate.admit(GatekeeperTest.IP,"synthetic")){if(a.allowed()){count++;a.complete(Gatekeeper.Outcome.SUCCESS);}}
            System.out.println("ADMITTED="+count);
        }
    }
}
