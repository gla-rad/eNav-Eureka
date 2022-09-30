package org.grad.eNav.eureka.config;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.SSLException;

/**
 * The Boostrap Configuration.
 *
 * @author Nikolaos Vastardis (email: Nikolaos.Vastardis@gla-rad.org)
 */
@Configuration
public class BootstrapConfig {

    /**
     * Load Keycloak configuration from application.properties or application.yml
     *
     * On multi-tenant scenarios, Keycloak will defer the resolution of a
     * KeycloakDeployment to the target application at the request-phase.
     *
     * A Request object is passed to the resolver and callers expect a complete
     * KeycloakDeployment. Based on this KeycloakDeployment, Keycloak will
     * resume authenticating and authorizing the request.
     *
     * This is required in a separate configuration according to:
     * https://stackoverflow.com/questions/57957006/unable-to-build-spring-based-project-for-authentication-using-keycloak
     *
     * Otherwise, a circular dependency issues appear during startup.
     *
     * @return The keycloak configuration resolver
     */
    @Bean
    public KeycloakConfigResolver keycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }

    /**
     * Normally internal clients use plain HTTP but the API-Gateway might be
     * configured with HTTPS. Assuming this service is not externally
     * available, we can allow any type of SSL certificates, since the ones
     * from the MCP don't usually have a hostname attributed.
     *
     * @return A custom HTTP connection with insecure trust manager policy
     * @throws SSLException For any SSL Exceptions thrown
     */
    @Bean
    public ClientHttpConnector customHttpClient() throws SSLException {
        // Create the SSL Context
        SslContext sslContext = SslContextBuilder
                .forClient()
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();
        // Create the HTTP client
        HttpClient httpClient = HttpClient.create()
                .secure(ssl -> ssl.sslContext(sslContext));
        // And return the custom connector
        return new ReactorClientHttpConnector(httpClient);
    }
}
