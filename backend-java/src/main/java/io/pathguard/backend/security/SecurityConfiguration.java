package io.pathguard.backend.security;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.util.StringUtils;

@Configuration
public class SecurityConfiguration {
    @Bean
    ConnectorBearerTokenFilter connectorBearerTokenFilter(ObjectProvider<ConnectorTokenAuthenticator> authenticators) {
        ConnectorTokenAuthenticator authenticator = authenticators.getIfAvailable(() -> token -> java.util.Optional.empty());
        return new ConnectorBearerTokenFilter(authenticator);
    }

    @Bean
    FilterRegistrationBean<ConnectorBearerTokenFilter> disableContainerFilterRegistration(
            ConnectorBearerTokenFilter filter) {
        FilterRegistrationBean<ConnectorBearerTokenFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    SecurityFilterChain pathGuardSecurityFilterChain(
            HttpSecurity http,
            ConnectorBearerTokenFilter connectorFilter,
            @Value("${pathguard.security.jwt-issuer-uri:}") String issuerUri,
            @Value("${pathguard.security.jwt-jwk-set-uri:}") String jwkSetUri) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/connectors/enroll").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/site-connector/heartbeat").hasRole("CONNECTOR")
                        .requestMatchers(HttpMethod.GET, "/api/v1/connectors/*/status").hasRole("HUMAN")
                        .requestMatchers(HttpMethod.POST, "/api/v1/connectors/enrollments").hasRole("TENANT_ADMIN")
                        .requestMatchers(HttpMethod.POST,
                                "/api/v1/aws/connections/prepare", "/api/v1/aws/connections/test")
                        .hasRole("TENANT_ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/v1/aws/connections/*/inventory").hasRole("HUMAN")
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/connectors/**").hasRole("TENANT_ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/v1/evidence/bundles").hasRole("CONNECTOR")
                        .requestMatchers("/api/v1/**").hasRole("HUMAN")
                        .anyRequest().denyAll())
                .addFilterBefore(connectorFilter, AnonymousAuthenticationFilter.class);

        if (StringUtils.hasText(issuerUri)) {
            JwtDecoder decoder;
            if (StringUtils.hasText(jwkSetUri)) {
                NimbusJwtDecoder jwkSetDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
                jwkSetDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuerUri));
                decoder = jwkSetDecoder;
            } else {
                decoder = JwtDecoders.fromIssuerLocation(issuerUri);
            }
            http.oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt
                    .decoder(decoder)
                    .jwtAuthenticationConverter(token ->
                            (AbstractAuthenticationToken) new TenantJwtAuthenticationConverter().convert(token))));
        }
        return http.build();
    }
}
