package dev.gatekeeper;

import java.net.InetAddress;
import java.util.Objects;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Explicit integration around a Spring AuthenticationManager. The caller supplies the
 * transport-derived source; no user-controlled authentication details are trusted.
 * This is not an auto-configured filter or a replacement for Spring Security.
 */
public final class SpringAuthenticationGate {
    private final Gatekeeper gate;
    private final AuthenticationManager delegate;
    public SpringAuthenticationGate(Gatekeeper gate, AuthenticationManager delegate) {
        this.gate = Objects.requireNonNull(gate);
        this.delegate = Objects.requireNonNull(delegate);
    }
    /** Contains no policy details or account-existence information for public responses. */
    public static final class AdmissionRejectedException extends AuthenticationException {
        public AdmissionRejectedException() { super("Authentication unavailable"); }
    }
    public Authentication authenticate(InetAddress source, Authentication request) {
        Objects.requireNonNull(request);
        if (request.isAuthenticated()) throw new IllegalArgumentException("Unauthenticated request required");
        try (Gatekeeper.Attempt attempt = gate.admit(source, request.getName())) {
            if (!attempt.allowed()) throw new AdmissionRejectedException();
            try {
                Authentication result = delegate.authenticate(request);
                if (result == null || !result.isAuthenticated()) {
                    attempt.complete(Gatekeeper.Outcome.INVALID_CREDENTIALS);
                    throw new BadCredentialsException("Authentication failed");
                }
                attempt.complete(Gatekeeper.Outcome.SUCCESS);
                return result;
            } catch (BadCredentialsException | UsernameNotFoundException e) {
                attempt.complete(Gatekeeper.Outcome.INVALID_CREDENTIALS);
                throw new BadCredentialsException("Authentication failed");
            }
            // Other exceptions close as ERROR: a service outage is not a bad password.
        }
    }
}
