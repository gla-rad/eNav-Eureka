/*
 * Copyright (c) 2021 GLA Research and Development Directorate
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.grad.eNav.eureka.config;

import de.codecentric.boot.admin.server.web.client.HttpHeadersProvider;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootProperties;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.security.Principal;

/**
 * The Web Security Configuration.
 *
 * @author Nikolaos Vastardis (email: Nikolaos.Vastardis@gla-rad.org)
 */
@Slf4j
@Configuration
@EnableWebSecurity
@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
class WebSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

    /**
     * A session based registry to be used by an authentication strategy.
     *
     * @return The session based registry
     */
    @Bean
    protected SessionRegistry buildSessionRegistry() {
        return new SessionRegistryImpl();
    }

    /**
     * The Session authentication strategy bean, linked to a session based
     * strategy.
     *
     * @return The session authentication strategy
     */
    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(buildSessionRegistry());
    }

    /**
     * Load Keycloak configuration from application.properties or application.yml
     *
     * @return The keycloak configuration resolver
     */
    @Bean
    public KeycloakConfigResolver keycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }

    /**
     * {@link HttpHeadersProvider} used to populate the {@link HttpHeaders} for
     * accessing the state of the discovered clients.
     *
     * @param keycloak      The keycloak admin bean
     * @return The HTTP headers populated with the spring boot admin token
     */
    @Bean
    public HttpHeadersProvider keycloakBearerAuthHeaderProvider(Keycloak keycloak) {
        return (app) -> {
            HttpHeaders headers = new HttpHeaders();
            try {
                String accessToken = keycloak.tokenManager().getAccessTokenString();
                headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
            } catch(Exception ex) {
                log.error(ex.getMessage());
            }
            return headers;
        };
    }

    /**
     * The Keycloak Admin client that provides the service-account Access-Token
     *
     * @param props         The keycloak configuration properties
     * @return The keycloak admin bean
     */
    @Bean
    public Keycloak keycloak(KeycloakSpringBootProperties props) {
        return KeycloakBuilder.builder()
                .serverUrl(props.getAuthServerUrl())
                .realm(props.getRealm())
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .clientId(props.getResource())
                .clientSecret((String)props.getCredentials().get("secret"))
                .build();
    }

    /**
     * Use {@link KeycloakAuthenticationProvider} to link to the keycloak
     * authentication. It also appends the ROLE prexis to all authority
     * mappings.
     *
     * @param auth              The authentication manager builder
     * @throws Exception
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        SimpleAuthorityMapper grantedAuthorityMapper = new SimpleAuthorityMapper();
        grantedAuthorityMapper.setPrefix("ROLE_");
        grantedAuthorityMapper.setConvertToUpperCase(true);

        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(grantedAuthorityMapper);
        auth.authenticationProvider(keycloakAuthenticationProvider);
    }

    /**
     * Allows to inject requests scoped wrapper for {@link KeycloakSecurityContext}.
     * <p>
     * Returns the {@link KeycloakSecurityContext} from the Spring
     * {@link ServletRequestAttributes}'s {@link Principal}.
     * <p>
     * The principal must support retrieval of the KeycloakSecurityContext, so at
     * this point, only {@link KeycloakPrincipal} values and
     * {@link KeycloakAuthenticationToken} are supported.
     *
     * @return the current <code>KeycloakSecurityContext</code>
     */
    @Bean
    @Scope(scopeName = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
    public KeycloakSecurityContext provideKeycloakSecurityContext() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        Principal principal = attributes.getRequest().getUserPrincipal();
        if (principal == null) {
            return null;
        }

        // Check for authenticated users
        if (principal instanceof KeycloakAuthenticationToken) {
            principal = Principal.class.cast(KeycloakAuthenticationToken.class.cast(principal).getPrincipal());
        }

        // Check for tokens based on context - i.e. other services
        if (principal instanceof KeycloakPrincipal) {
            return KeycloakPrincipal.class.cast(principal).getKeycloakSecurityContext();
        }

        return null;
    }

    /**
     * Specified the HTTP security configuration. All actuator endpoints apart
     * from the health and the info one are protected, while the admin menu
     * required admin priviladges.
     *
     * @param httpSecurity      The HTTP security
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        super.configure(httpSecurity);
        httpSecurity
                .csrf().disable()
                .authorizeRequests()
                .antMatchers(
                        "/eureka",       //registration endpoint
                        "/**/*.css",                //css files
                        "/admin/applications",      //admin applications
                        "/admin/img/**",            //admin image files
                        "/admin/third-party/**"     //admin third parties
                ).permitAll()
                .requestMatchers(EndpointRequest.to( //
                        InfoEndpoint.class,         //info endpoints
                        HealthEndpoint.class        //health endpoints
                )).permitAll()
                .requestMatchers(EndpointRequest.toAnyEndpoint())
                .hasRole("ACTUATOR")
                .antMatchers("/admin")
                .hasRole("ADMIN")
                .anyRequest()
                .permitAll();
    }

}
