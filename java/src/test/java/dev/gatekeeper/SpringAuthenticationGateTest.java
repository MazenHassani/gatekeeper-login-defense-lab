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

    @Test void realDaoProviderVerifiesPasswordsAndProtectsUnknownUserTimingPath() {
        var bcrypt = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(4); // Test cost only.
        var encoded = bcrypt.encode("synthetic-password");
        var matches = new AtomicInteger();
        var encoder = new org.springframework.security.crypto.password.PasswordEncoder() {
            public String encode(CharSequence raw) { return bcrypt.encode(raw); }
            public boolean matches(CharSequence raw, String hash) {
                matches.incrementAndGet();
                return bcrypt.matches(raw, hash);
            }
        };
        org.springframework.security.core.userdetails.UserDetailsService users = name -> {
            if (!name.equals("demo")) throw new org.springframework.security.core.userdetails.UsernameNotFoundException("not exposed");
            return org.springframework.security.core.userdetails.User.withUsername("demo").password(encoded).roles("USER").build();
        };
        var provider = new org.springframework.security.authentication.dao.DaoAuthenticationProvider(users);
        provider.setPasswordEncoder(encoder);
        var manager = new ProviderManager(provider);
        var gate = new Gatekeeper(GatekeeperTest.policy(100, 1, 1, Policy.Mode.ENFORCE), new BoundedMemoryStore(100));
        var adapter = new SpringAuthenticationGate(gate, manager);
        assertTrue(adapter.authenticate(GatekeeperTest.IP,
            UsernamePasswordAuthenticationToken.unauthenticated("demo", "synthetic-password")).isAuthenticated());
        assertThrows(BadCredentialsException.class, () -> adapter.authenticate(GatekeeperTest.IP,
            UsernamePasswordAuthenticationToken.unauthenticated("demo", "wrong")));
        assertThrows(BadCredentialsException.class, () -> adapter.authenticate(GatekeeperTest.IP,
            UsernamePasswordAuthenticationToken.unauthenticated("unknown", "wrong")));
        // Includes Spring's actual dummy password comparison for unknown users.
        assertEquals(3, matches.get());
        assertThrows(SpringAuthenticationGate.AdmissionRejectedException.class, () -> adapter.authenticate(GatekeeperTest.IP,
            UsernamePasswordAuthenticationToken.unauthenticated("demo", "synthetic-password")));
        assertEquals(3, matches.get()); // Denial did not reach the real provider's encoder.
        assertEquals(0, gate.metrics().inFlight());
    }

}
