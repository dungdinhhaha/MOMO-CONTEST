package io.pathguard.backend.connectors;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class ConnectorRegistryService {
    private static final int DEFAULT_ENROLLMENT_SECONDS = 600;
    private static final int MIN_ENROLLMENT_SECONDS = 60;
    private static final int MAX_ENROLLMENT_SECONDS = 900;
    private static final long CONNECTOR_CREDENTIAL_SECONDS = 90L * 24 * 60 * 60;
    private static final int TOKEN_RANDOM_BYTES = 32;

    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final SecureRandom secureRandom;

    @Autowired
    public ConnectorRegistryService(JdbcTemplate jdbc) {
        this(jdbc, Clock.systemUTC(), new SecureRandom());
    }

    ConnectorRegistryService(JdbcTemplate jdbc, Clock clock, SecureRandom secureRandom) {
        this.jdbc = jdbc;
        this.clock = clock;
        this.secureRandom = secureRandom;
    }

    public EnrollmentIssued createEnrollment(UUID tenantId, String subject, String connectorType,
                                              String connectionId, String siteId, String zoneId,
                                              Integer requestedTtlSeconds) {
        String normalizedType = normalizeType(connectorType);
        String normalizedConnection = normalizeReference(connectionId, "connectionId", true);
        String normalizedSite = normalizeReference(siteId, "siteId", true);
        String normalizedZone = normalizeReference(zoneId, "zoneId", true);
        if (("AWS".equals(normalizedType) || "CI_CD".equals(normalizedType)) && normalizedConnection == null) {
            throw badRequest("connectionId is required for AWS and CI_CD connectors");
        }
        if ("ON_PREM".equals(normalizedType) && normalizedSite == null) {
            throw badRequest("siteId is required for on-prem connectors");
        }
        int ttl = requestedTtlSeconds == null ? DEFAULT_ENROLLMENT_SECONDS : requestedTtlSeconds;
        if (ttl < MIN_ENROLLMENT_SECONDS || ttl > MAX_ENROLLMENT_SECONDS) {
            throw badRequest("expiresInSeconds must be between 60 and 900");
        }
        if (tenantId == null || subject == null || subject.isBlank() || subject.length() > 256) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Valid tenant identity is required");
        }

        UUID enrollmentId = UUID.randomUUID();
        UUID connectorId = UUID.randomUUID();
        Instant createdAt = Instant.now(clock);
        Instant expiresAt = createdAt.plusSeconds(ttl);
        String rawToken = newRawToken("pge_");

        jdbc.update("""
                INSERT INTO pathguard_connector_enrollments
                    (enrollment_id, tenant_id, connector_id, connector_type, connection_id, site_id, zone_id,
                     enrollment_token_hash, created_by, created_at, expires_at, consumed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                enrollmentId, tenantId, connectorId, normalizedType, normalizedConnection, normalizedSite,
                normalizedZone, sha256(rawToken), subject, java.sql.Timestamp.from(createdAt),
                java.sql.Timestamp.from(expiresAt));

        return new EnrollmentIssued(enrollmentId, connectorId, normalizedType, normalizedConnection,
                normalizedSite, normalizedZone, rawToken, createdAt, expiresAt);
    }

    @Transactional
    public ConnectorIssued exchangeEnrollment(String rawEnrollmentToken) {
        if (!isTokenShapeValid(rawEnrollmentToken, "pge_")) {
            throw unauthorizedEnrollment();
        }
        List<EnrollmentRow> rows = jdbc.query("""
                SELECT enrollment_id, tenant_id, connector_id, connector_type, connection_id, site_id, zone_id,
                       created_by, created_at, expires_at
                  FROM pathguard_connector_enrollments
                 WHERE enrollment_token_hash = ? AND consumed_at IS NULL AND expires_at > CURRENT_TIMESTAMP
                 FOR UPDATE
                """, ENROLLMENT_ROW_MAPPER, sha256(rawEnrollmentToken));
        if (rows.size() != 1) {
            throw unauthorizedEnrollment();
        }

        EnrollmentRow enrollment = rows.getFirst();
        Instant now = Instant.now(clock);
        Instant credentialExpiresAt = now.plusSeconds(CONNECTOR_CREDENTIAL_SECONDS);
        String rawCredential = newRawToken("pgc_");

        int consumed = jdbc.update("""
                UPDATE pathguard_connector_enrollments
                   SET consumed_at = ?
                 WHERE enrollment_id = ? AND consumed_at IS NULL AND expires_at > CURRENT_TIMESTAMP
                """, java.sql.Timestamp.from(now), enrollment.enrollmentId());
        if (consumed != 1) {
            throw unauthorizedEnrollment();
        }

        jdbc.update("""
                INSERT INTO pathguard_connectors
                    (connector_id, tenant_id, connector_type, connection_id, site_id, zone_id, credential_hash,
                     created_by, created_at, expires_at, last_seen_at, revoked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                enrollment.connectorId(), enrollment.tenantId(), enrollment.connectorType(),
                enrollment.connectionId(), enrollment.siteId(), enrollment.zoneId(), sha256(rawCredential),
                enrollment.createdBy(), java.sql.Timestamp.from(now), java.sql.Timestamp.from(credentialExpiresAt));

        return new ConnectorIssued(enrollment.connectorId(), enrollment.tenantId(), enrollment.connectorType(),
                enrollment.connectionId(), enrollment.siteId(), enrollment.zoneId(), rawCredential, now,
                credentialExpiresAt);
    }

    public List<ConnectorView> listForTenant(UUID tenantId) {
        if (tenantId == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Valid tenant identity is required");
        }
        return jdbc.query("""
                SELECT connector_id, connector_type, connection_id, site_id, zone_id, created_at, expires_at,
                       last_seen_at, revoked_at
                  FROM pathguard_connectors
                 WHERE tenant_id = ?
                 ORDER BY created_at DESC
                """, CONNECTOR_VIEW_ROW_MAPPER, tenantId);
    }

    public void revoke(UUID tenantId, UUID connectorId) {
        if (tenantId == null || connectorId == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Connector not found");
        }
        int updated = jdbc.update("""
                UPDATE pathguard_connectors
                   SET revoked_at = CURRENT_TIMESTAMP
                 WHERE connector_id = ? AND tenant_id = ? AND revoked_at IS NULL
                """, connectorId, tenantId);
        if (updated != 1) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Connector not found");
        }
    }

    private String newRawToken(String prefix) {
        byte[] bytes = new byte[TOKEN_RANDOM_BYTES];
        secureRandom.nextBytes(bytes);
        return prefix + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String sha256(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    static boolean isTokenShapeValid(String token, String prefix) {
        return token != null && token.length() >= prefix.length() + 40 && token.length() <= 128
                && token.startsWith(prefix);
    }

    private static String normalizeType(String value) {
        if (value == null) {
            throw badRequest("connectorType must be AWS, ON_PREM, or CI_CD");
        }
        String normalized = value.trim().toUpperCase(java.util.Locale.ROOT);
        if (!normalized.equals("AWS") && !normalized.equals("ON_PREM") && !normalized.equals("CI_CD")) {
            throw badRequest("connectorType must be AWS, ON_PREM, or CI_CD");
        }
        return normalized;
    }

    private static String normalizeReference(String value, String name, boolean nullable) {
        if (value == null || value.isBlank()) {
            if (nullable) {
                return null;
            }
            throw badRequest(name + " is required");
        }
        String normalized = value.trim();
        if (normalized.length() > 128 || !normalized.matches("[A-Za-z0-9._:-]+")) {
            throw badRequest(name + " must use 1-128 letters, digits, dot, underscore, colon, or hyphen");
        }
        return normalized;
    }

    private static ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    private static ResponseStatusException unauthorizedEnrollment() {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Enrollment token is invalid, expired, or used");
    }

    private record EnrollmentRow(UUID enrollmentId, UUID tenantId, UUID connectorId, String connectorType,
                                 String connectionId, String siteId, String zoneId, String createdBy,
                                 Instant createdAt, Instant expiresAt) { }

    private static final RowMapper<EnrollmentRow> ENROLLMENT_ROW_MAPPER = (rs, row) -> new EnrollmentRow(
            rs.getObject("enrollment_id", UUID.class), rs.getObject("tenant_id", UUID.class),
            rs.getObject("connector_id", UUID.class), rs.getString("connector_type"),
            rs.getString("connection_id"), rs.getString("site_id"), rs.getString("zone_id"),
            rs.getString("created_by"), rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("expires_at").toInstant());

    private static final RowMapper<ConnectorView> CONNECTOR_VIEW_ROW_MAPPER = (rs, row) -> new ConnectorView(
            rs.getObject("connector_id", UUID.class), rs.getString("connector_type"),
            rs.getString("connection_id"), rs.getString("site_id"), rs.getString("zone_id"),
            rs.getTimestamp("created_at").toInstant(), rs.getTimestamp("expires_at").toInstant(),
            timestampToInstant(rs.getTimestamp("last_seen_at")), timestampToInstant(rs.getTimestamp("revoked_at")));

    private static Instant timestampToInstant(java.sql.Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    public record EnrollmentIssued(UUID enrollmentId, UUID connectorId, String connectorType, String connectionId,
                                    String siteId, String zoneId, String enrollmentToken, Instant createdAt,
                                    Instant expiresAt) { }

    public record ConnectorIssued(UUID connectorId, UUID tenantId, String connectorType, String connectionId,
                                  String siteId, String zoneId, String connectorToken, Instant createdAt,
                                  Instant expiresAt) { }

    public record ConnectorView(UUID connectorId, String connectorType, String connectionId, String siteId,
                                String zoneId, Instant createdAt, Instant expiresAt, Instant lastSeenAt,
                                Instant revokedAt) { }
}
