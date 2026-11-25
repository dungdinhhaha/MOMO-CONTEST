package io.pathguard.backend.evidence;

import io.pathguard.backend.evidence.EvidenceBundleService.EvidencePage;
import io.pathguard.backend.evidence.EvidenceBundleService.IngestResult;
import io.pathguard.backend.security.ConnectorIdentity;
import io.pathguard.backend.security.TenantIdentity;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequestMapping("/api/v1")
public class EvidenceBundleController {
    private final EvidenceBundleService service;

    public EvidenceBundleController(EvidenceBundleService service) {
        this.service = service;
    }

    @PostMapping(path = "/evidence/bundles", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<IngestResult> ingest(
            @RequestBody byte[] body,
            @RequestHeader(name = "Content-Length", required = false) Long contentLength,
            Authentication authentication) {
        if (contentLength != null && contentLength > EvidenceBundleValidator.MAX_BUNDLE_BYTES) {
            throw new PayloadTooLargeException();
        }
        if (authentication == null || !(authentication.getPrincipal() instanceof ConnectorIdentity connector)) {
            throw new InvalidEvidenceBundleException("Connector authentication is required");
        }
        IngestResult result = service.ingest(body, connector);
        return ResponseEntity.status(result.duplicate() ? HttpStatus.OK : HttpStatus.CREATED).body(result);
    }

    @GetMapping(path = "/evidence", produces = MediaType.APPLICATION_JSON_VALUE)
    public EvidencePage list(
            Authentication authentication,
            @RequestParam(name = "since", required = false) Instant since,
            @RequestParam(name = "until", required = false) Instant until,
            @RequestParam(defaultValue = "50") int limit,
            @RequestParam(defaultValue = "0") int offset) {
        if (authentication == null || !(authentication.getPrincipal() instanceof TenantIdentity tenant)) {
            throw new InvalidEvidenceQueryException("Human tenant authentication is required");
        }
        return service.list(tenant, since, until, limit, offset);
    }
}
