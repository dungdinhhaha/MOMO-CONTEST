package io.pathguard.backend.evidence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pathguard.backend.evidence.EvidenceBundleRepository.StoredEvidenceBundle;
import io.pathguard.backend.security.ConnectorIdentity;
import io.pathguard.backend.security.TenantIdentity;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EvidenceBundleServiceTenantScopeTest {
    private static final UUID TENANT_A = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    private static final UUID TENANT_B = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    private static final UUID CONNECTOR_A = UUID.fromString("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    private EvidenceBundleRepository repository;
    private EvidenceBundleService service;

    @BeforeEach
    void setUp() {
        repository = mock(EvidenceBundleRepository.class);
        service = new EvidenceBundleService(new EvidenceBundleValidator(new ObjectMapper()), repository,
                new ObjectMapper());
        when(repository.findByTenant(any(), any(), any(), anyInt(), anyInt()))
                .thenReturn(List.of());
    }

    @Test
    void evidenceReadsUseOnlyTheAuthenticatedTenantIdentity() {
        service.list(new TenantIdentity(TENANT_A, "alice"), null, null, 50, 0);
        service.list(new TenantIdentity(TENANT_B, "bob"), null, null, 50, 0);

        verify(repository).findByTenant(eq(TENANT_A), isNull(), isNull(), eq(50), eq(0));
        verify(repository).findByTenant(eq(TENANT_B), isNull(), isNull(), eq(50), eq(0));
    }

    @Test
    void ingestBindsStoredTenantAndConnectorFromAuthenticatedPrincipal() {
        when(repository.insert(any(StoredEvidenceBundle.class))).thenAnswer(invocation ->
                ((StoredEvidenceBundle) invocation.getArgument(0)).bundleId());
        ConnectorIdentity identity = new ConnectorIdentity(TENANT_A, CONNECTOR_A, "AWS", "aws-prod", null, null);
        String payload = "{\"schema_version\":\"pathguard.evidence-bundle.v1\","
                + "\"collected_at\":\"2026-11-24T10:01:00Z\",\"source_type\":\"AWS\","
                + "\"connection_id\":\"aws-prod\",\"records\":[{\"id\":\"r1\","
                + "\"evidence_type\":\"config\",\"resource_key\":\"acct/region/vpc-1\","
                + "\"observed_at\":\"2026-11-24T10:00:00Z\",\"payload\":{}}],"
                + "\"coverage\":{\"status\":\"complete\",\"window_start\":\"2026-11-24T09:00:00Z\","
                + "\"window_end\":\"2026-11-24T10:00:00Z\"}}";

        var result = service.ingest(payload.getBytes(StandardCharsets.UTF_8), identity);

        org.mockito.ArgumentCaptor<StoredEvidenceBundle> captor =
                org.mockito.ArgumentCaptor.forClass(StoredEvidenceBundle.class);
        verify(repository).insert(captor.capture());
        assertEquals(captor.getValue().bundleId(), result.bundleId());
        assertEquals(TENANT_A, captor.getValue().tenantId());
        assertEquals(CONNECTOR_A, captor.getValue().connectorId());
    }
}
