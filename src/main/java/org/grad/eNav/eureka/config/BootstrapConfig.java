package org.grad.eNav.eureka.config;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
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
