package dev.gatekeeper;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Exact-address proxy trust, disabled unless the operator supplies trusted peers. No DNS lookups. */
public final class ClientAddress {
    private ClientAddress() {}
    public static InetAddress literal(String text) {
        if (text == null || text.length() > 45 || text.isBlank() || text.indexOf('%') >= 0) {
            throw new IllegalArgumentException("IP literal required");
        }
        try {
            if (text.indexOf(':') >= 0) {
                if (!text.matches("[0-9a-fA-F:.]+")) throw new IllegalArgumentException("IP literal required");
                return InetAddress.getByName(text); // ':' plus character restriction prevents host/DNS names.
            }
            String[] parts = text.split("\\.", -1);
            if (parts.length != 4) throw new IllegalArgumentException("IPv4 literal required");
            byte[] bytes = new byte[4];
            for (int i = 0; i < 4; i++) {
                if (!parts[i].matches("0|[1-9][0-9]{0,2}")) throw new IllegalArgumentException("Canonical IPv4 required");
                int value = Integer.parseInt(parts[i]);
                if (value > 255) throw new IllegalArgumentException("Invalid IPv4");
                bytes[i] = (byte) value;
            }
            return InetAddress.getByAddress(bytes);
        } catch (UnknownHostException e) { throw new IllegalArgumentException("Invalid IP literal", e); }
    }
    /**
     * Read peer from the original transport socket. Join repeated XFF fields with commas first.
     * An untrusted peer's forwarding header is ignored, including malformed content.
     * Trusted proxies must append/replace XFF predictably and block direct origin access.
     */
    public static InetAddress resolve(InetAddress peer, String forwardedFor, Set<InetAddress> trustedProxies) {
        if (peer == null || trustedProxies == null) throw new IllegalArgumentException("Peer and trust set required");
        if (!trustedProxies.contains(peer) || forwardedFor == null || forwardedFor.isBlank()) return peer;
        if (forwardedFor.length() > 1024) throw new IllegalArgumentException("Forwarding chain too long");
        String[] items = forwardedFor.split(",", -1);
        if (items.length > 8) throw new IllegalArgumentException("Too many proxy hops");
        List<InetAddress> addresses = new ArrayList<>();
        for (String item : items) addresses.add(literal(item.trim()));
        InetAddress candidate = peer;
        for (int i = addresses.size() - 1; i >= 0 && trustedProxies.contains(candidate); i--) {
            candidate = addresses.get(i);
        }
        return candidate;
    }
}
