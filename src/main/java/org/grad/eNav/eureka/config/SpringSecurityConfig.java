/*
 * Copyright (c) 2023 GLA Research and Development Directorate
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

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import de.codecentric.boot.admin.server.web.client.HttpHeadersProvider;
import jakarta.servlet.DispatcherType;
import org.grad.eNav.eureka.config.keycloak.KeycloakGrantedAuthoritiesMapper;
import org.grad.eNav.eureka.config.keycloak.KeycloakJwtAuthenticationConverter;
import org.grad.eNav.eureka.config.keycloak.KeycloakLogoutHandler;
import org.grad.eNav.eureka.config.keycloak.KeycloakOAuth2AuthorizedClientProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.ForwardedHeaderFilter;

import java.util.Optional;

/**
 * The Web Security Configuration.
 *
 * This is the security definition for the security configuration and the filter
 * chains the service.
 *
 * @author Nikolaos Vastardis (email: Nikolaos.Vastardis@gla-rad.org)
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@ConditionalOnProperty(value = "keycloak.enabled", matchIfMissing = true)
class SpringSecurityConfig {

    /**
     * The default application name.
     */
    @Value("${keycloak.clientId:eureka}")
    private String clientId;

    // Class Variables
    private final AdminServerProperties adminServer;
    private final SecurityProperties security;

    /**
     * The Class Constructor.
     *
     * @param adminServerProperties       The Springboot admin server properties
     * @param securityProperties          The security properties
     */
    public SpringSecurityConfig(AdminServerProperties adminServerProperties,
                                SecurityProperties securityProperties) {
        this.adminServer = adminServerProperties;
        this.security = securityProperties;

    }

    /**
     * The REST Template.
     *
     * @return the REST template
     */
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    /**
     * Define a slightly more flexible HTTP Firewall configuration that allows
     * characters like semicolons, slashes and percentages.
     */
    @Bean
    protected HttpFirewall securityHttpFirewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowSemicolon(true);
        firewall.setAllowUrlEncodedSlash(true);
        firewall.setAllowUrlEncodedPercent(true);
        return firewall;
    }

    /**
     * Forwarded header filter registration bean.
     * <p>
     * This corrects the urls produced by the microservice when accessed from a proxy server.
     * E.g. Api gateway:
     * my-service.com/style.css -> api-gateway.com/my-service/style.css
     * <p>
     * The proxy server should be sending the forwarded header address as a header
     * which this filter will pick up and resolve for us.
     *
     * @return the filter registration bean
     */
    @Bean
    protected FilterRegistrationBean<ForwardedHeaderFilter> forwardedHeaderFilter() {
        final FilterRegistrationBean<ForwardedHeaderFilter> filterRegistrationBean = new FilterRegistrationBean<>();
        filterRegistrationBean.setFilter(new ForwardedHeaderFilter());
        filterRegistrationBean.setDispatcherTypes(DispatcherType.REQUEST, DispatcherType.ASYNC, DispatcherType.ERROR);
        filterRegistrationBean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return filterRegistrationBean;
    }

    /**
     * The OAuth2 Authorized Client Manager bean provider. Since the new Spring
     * Security 5 framework, we can use the OAuth2AuthorizedClientService
     * class to authorize our clients, as long as the configuration is found
     * in the application.properties file.
     *
     * @param clientRegistrationRepository the client registration repository
     * @param clientService the OAuth2 authorized client service
     * @return the OAuth2 authorized client manager to authorize the feign requests
     */
    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clientRegistrationRepository,
                                                          OAuth2AuthorizedClientService clientService) {
        // First create an OAuth2 Authorized Client Provider
        OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials()
                .build();

        // Create a client manage to handle the Feign authorization
        AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                clientRegistrationRepository,
                clientService
        );

        // Set the client provider in the client
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        // And return
        return authorizedClientManager;
    }

    /**
     * The Spring Boot Admin operation in our services is also bound by OAuth2
     * and Keycloak. Therefore, for each request we need to service account
     * access token (which is generated via a credential flow) to be added to
     * the request headers. Spring Boot Admin allows us to add this manually
     * using a HttpHeadersProvider bean. But be careful, by default Spring Boot
     * Admin does not include the "Authorization" header in its requests, so
     * we need to configure the application properties to block this
     * functionality.
     * <p/>
     * spring.boot.admin.instance-proxy.ignored-headers=Cookie,Set-Cookie
     *
     * @param keycloakOAuth2AuthorizedClientProvider    The Keycloak OAuth2 Authorised Client provider
     * @return the Spring Boot Admin HTTP header provider
     */
    @Bean
    public HttpHeadersProvider SpringBootAdminHttpHeadersProvider(KeycloakOAuth2AuthorizedClientProvider keycloakOAuth2AuthorizedClientProvider) {
        return instance -> {
            HttpHeaders httpHeaders = new HttpHeaders();
            Optional.of(keycloakOAuth2AuthorizedClientProvider)
                    .map(KeycloakOAuth2AuthorizedClientProvider::getClient)
                    .map(OAuth2AuthorizedClient::getAccessToken)
                    .map(OAuth2AccessToken::getTokenValue)
                    .ifPresent(token -> {
                        httpHeaders.add("Authorization", "Bearer " + token);
                    });
            return httpHeaders;
        };
    }

    /**
     * Specify a converter for the Keycloak authority claims.
     *
     * @return the Keycloak JWT Authentication Converter
     */
    @Bean
    protected Converter<Jwt, ? extends AbstractAuthenticationToken> keycloakJwtAuthenticationConverter() {
        return new KeycloakJwtAuthenticationConverter(this.clientId);
    }

    /**
     * Specify a mapper for the keycloak authority claims.
     *
     * @return the Keycloak Granted Authority Mapper
     */
    @Bean
    protected GrantedAuthoritiesMapper keycloakGrantedAuthoritiesMapper() {
        return new KeycloakGrantedAuthoritiesMapper(this.clientId);
    }

    /**
     * Define a logout handler for handling Keycloak logouts.
     *
     * @param restTemplate the REST template
     * @return the Keycloak logout handler
     */
    @Bean
    protected KeycloakLogoutHandler keycloakLogoutHandler(RestTemplate restTemplate) {
        return new KeycloakLogoutHandler(restTemplate);
    }

    /**
     * Define the session authentication strategy which uses a simple session
     * registry to store our current sessions.
     *
     * @return the session authentication strategy
     */
    @Bean
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    /**
     * Defines the security web-filter chains.
     * </p>
     * This is the main security chain of the service depending on keycloak.
     * Allows open access to the health and info actuator endpoints.
     * All other actuator endpoints are only available for the actuator role.
     * Finally, all other exchanges need to be authenticated.
     *
     * @param http the HTTP security
     * @param clientRegistrationRepository the client registration repository
     * @param restTemplate the employed REST template
     * @return the JWT security filter chain
     * @throws Exception for any operational exceptions
     */
    @Order(2)
    @Bean
    public SecurityFilterChain filterChainJwt(HttpSecurity http,
                                              ClientRegistrationRepository clientRegistrationRepository,
                                              RestTemplate restTemplate) throws Exception {
        // Setup a login success handler
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setTargetUrlParameter("redirectTo");
        successHandler.setDefaultTargetUrl(this.adminServer.getContextPath() + "/");

        // Authenticate through configured OpenID Provider
        http.oauth2Login(login -> login
                .loginPage("/oauth2/authorization/keycloak")
                .successHandler(successHandler)
//                .authorizationEndpoint().baseUri("/oauth2/authorization/keycloak")
//                .authorizationRequestRepository(new HttpSessionOAuth2AuthorizationRequestRepository())
        );
        // Also, logout at the OpenID Connect provider
        http.logout(logout -> logout
                .deleteCookies("JSESSIONID")
                .addLogoutHandler(keycloakLogoutHandler(restTemplate))
                .logoutSuccessUrl("/")
//                .logoutSuccessHandler(new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository))
        );
        // Require authentication for all requests
        http
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers(EndpointRequest.to(
                                InfoEndpoint.class,     //info endpoints
                                HealthEndpoint.class    //health endpoints
                        )).permitAll()
                        .requestMatchers(EndpointRequest.toAnyEndpoint()).hasRole("ACTUATOR")
                        .requestMatchers(new AntPathRequestMatcher(this.adminServer.path("/assets/**"))).permitAll()
                        .requestMatchers(new AntPathRequestMatcher(this.adminServer.path("/variables.css"))).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/config/**")).hasRole("BASIC_AUTH")
                        .dispatcherTypeMatchers(DispatcherType.ASYNC).permitAll()
                        .requestMatchers(
                                "/",        //root
                                "/eureka/",          //registration endpoint
                                "/eureka/apps/**",   //application endpoints
                                "/eureka/css/**",    //css files
                                "/eureka/js/**",     //js files
                                "/error"             //the error endpoint - to handle the eureka re-registrations problem
                        ).permitAll()
                        .requestMatchers("/admin", "/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(keycloakJwtAuthenticationConverter())
                        )
                );

        // Disable the CSRF
        http.csrf(AbstractHttpConfigurer::disable);

        // Build and return
        return http.build();
    }

    /**
     * Defines the Basic Auth security web-filter chains.
     * </p>
     * This security filter chain only operates the Basic Auth security in
     * the configuration endpoint "/config/**". This should allow all other
     * service to connect and get their configuration.
     *
     * @param http the HTTP security
     * @param clientRegistrationRepository the client registration repository
     * @param restTemplate the employed REST template
     * @return the JWT security filter chain
     * @throws Exception for any operational exceptions
     */
    @Order(1)
    @Bean
    public SecurityFilterChain filterChainBasic(HttpSecurity http,
                                                ClientRegistrationRepository clientRegistrationRepository,
                                                RestTemplate restTemplate) throws Exception {
        http
                .securityMatcher(new AntPathRequestMatcher("/config/**"))
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .anyRequest().hasRole("BASIC_AUTH")
                )
                .httpBasic(Customizer.withDefaults());

        // Disable the CSRF
        http.csrf(AbstractHttpConfigurer::disable);

        // Build and return
        return http.build();
    }

    /**
     * An in-memory user details service that controls the access to the cloud
     * configuration server in this service.
     *
     * @return the cloud configuration user details service
     */
    @Bean
    UserDetailsService cloudConfigUserDetailsService() {
        UserDetails user = User
                .withUsername("user")
                .password("{noop}password") // Spring Security 5 requires password storage format
                .roles("BASIC_AUTH")
                .build();

        return new InMemoryUserDetailsManager(user);
    }

}
