package io.pathguard.backend.hostedgithub;

import io.pathguard.backend.hostedgithub.HostedGithubRepository.Source;
import io.pathguard.backend.hostedgithub.HostedGithubService.NewSource;
import io.pathguard.backend.security.TenantIdentity;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/hosted/github")
public class HostedGithubController {
    private final HostedGithubService service;

    public HostedGithubController(HostedGithubService service) {
        this.service = service;
    }

    @PostMapping
    public Source create(Authentication authentication, @RequestBody NewSource request) {
        requireAdmin(authentication);
        return service.create(tenant(authentication), request);
    }

    @GetMapping
    public List<Source> list(Authentication authentication) {
        return service.list(tenant(authentication));
    }

    @PostMapping("/{sourceId}/sync")
    public Source sync(Authentication authentication, @PathVariable UUID sourceId) {
        requireAdmin(authentication);
        return service.sync(tenant(authentication), sourceId);
    }

    @DeleteMapping("/{sourceId}")
    public void delete(Authentication authentication, @PathVariable UUID sourceId) {
        requireAdmin(authentication);
        service.disable(tenant(authentication), sourceId);
    }

    private static TenantIdentity tenant(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof TenantIdentity identity)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Verified tenant identity is required");
        }
        return identity;
    }

    private static void requireAdmin(Authentication authentication) {
        if (authentication == null || authentication.getAuthorities().stream()
                .noneMatch(authority -> "ROLE_TENANT_ADMIN".equals(authority.getAuthority()))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant administrator role is required");
        }
    }
}
