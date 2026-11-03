package dev.gatekeeper;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.*;

class SpringAuthenticationGateTest {
    @Test void realSpringContractRunsOnlyWhenAdmitted() {
        Gatekeeper gate=new Gatekeeper(GatekeeperTest.policy(10,1,1,Policy.Mode.ENFORCE),new BoundedMemoryStore(100));
        AtomicInteger called=new AtomicInteger();
        var adapter=new SpringAuthenticationGate(gate,auth->{called.incrementAndGet();throw new BadCredentialsException("private user detail");});
        var request=UsernamePasswordAuthenticationToken.unauthenticated("alice","not-logged");
        var failure=assertThrows(BadCredentialsException.class,()->adapter.authenticate(GatekeeperTest.IP,request));
        assertEquals("Authentication failed",failure.getMessage());
        assertThrows(SpringAuthenticationGate.AdmissionRejectedException.class,()->adapter.authenticate(GatekeeperTest.IP,request));
        assertEquals(1,called.get());assertEquals(0,gate.metrics().inFlight());
    }
    @Test void delegateAuthenticatesAndApplicationErrorsReleaseWithoutFalseFailure() {
        Gatekeeper gate=new Gatekeeper(GatekeeperTest.policy(100,1,1,Policy.Mode.ENFORCE),new BoundedMemoryStore(100));
        var request=UsernamePasswordAuthenticationToken.unauthenticated("alice","not-logged");
        var good=new SpringAuthenticationGate(gate,auth->UsernamePasswordAuthenticationToken.authenticated("alice",null,List.of()));
        assertTrue(good.authenticate(GatekeeperTest.IP,request).isAuthenticated());
        var broken=new SpringAuthenticationGate(gate,auth->{throw new AuthenticationServiceException("database unavailable");});
        assertThrows(AuthenticationServiceException.class,()->broken.authenticate(GatekeeperTest.IP,request));
        assertEquals(0,gate.metrics().credentialFailures());assertEquals(0,gate.metrics().inFlight());
        assertTrue(good.authenticate(GatekeeperTest.IP,request).isAuthenticated());
    }
    @Test void unverifiedDelegateResultIsNeverAccepted() {
        Gatekeeper gate=new Gatekeeper(GatekeeperTest.policy(100,1,1,Policy.Mode.ENFORCE),new BoundedMemoryStore(100));
        var request=UsernamePasswordAuthenticationToken.unauthenticated("alice","not-logged");
        var adapter=new SpringAuthenticationGate(gate,auth->auth);
        assertThrows(BadCredentialsException.class,()->adapter.authenticate(GatekeeperTest.IP,request));
        assertEquals(1,gate.metrics().credentialFailures());
    }
    @Test void preAuthenticatedInputCannotSkipVerification() {
        var gate=new Gatekeeper(GatekeeperTest.policy(100,1,1,Policy.Mode.ENFORCE),new BoundedMemoryStore(100));
        var adapter=new SpringAuthenticationGate(gate,auth->{fail("Already-authenticated input reached provider");return auth;});
        var request=UsernamePasswordAuthenticationToken.authenticated("alice",null,List.of());
        assertThrows(IllegalArgumentException.class,()->adapter.authenticate(GatekeeperTest.IP,request));
    }

}
