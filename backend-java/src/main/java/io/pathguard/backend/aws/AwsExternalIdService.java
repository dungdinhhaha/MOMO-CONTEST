package io.pathguard.backend.aws;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Derives a stable ExternalId scoped to this PathGuard tenant and connection reference. */
@Service
public class AwsExternalIdService {
    private final byte[] secret;

    public AwsExternalIdService(@Value("${pathguard.aws.external-id-hmac-secret:}") String secret) {
        this.secret = secret == null ? new byte[0] : secret.getBytes(StandardCharsets.UTF_8);
    }

    public String derive(UUID tenantId, String connectionId) {
        if (secret.length < 32) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "AWS connection setup is not configured by this PathGuard deployment");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            byte[] digest = mac.doFinal((tenantId + "\n" + connectionId).getBytes(StandardCharsets.UTF_8));
            return "pg-" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (java.security.GeneralSecurityException impossible) {
            throw new IllegalStateException("HMAC-SHA256 is unavailable", impossible);
        }
    }
}
