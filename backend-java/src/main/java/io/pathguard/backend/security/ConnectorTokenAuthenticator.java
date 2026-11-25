package io.pathguard.backend.security;

import java.util.Optional;

/** Resolves a raw bearer token to a connector identity without trusting request payload claims. */
public interface ConnectorTokenAuthenticator {
    Optional<ConnectorIdentity> authenticate(String rawToken);
}
