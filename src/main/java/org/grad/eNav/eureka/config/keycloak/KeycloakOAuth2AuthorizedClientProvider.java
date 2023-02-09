/*
 * Copyright (c) 2023 GLA Research and Development Directorate
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.grad.eNav.eureka.config.keycloak;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.stereotype.Component;

/**
 * The Keycloak OAuth2 Authorised Client Provider Component.
 *
 * In the eureka operation, we need to be able to generate service account
 * access tokens for the Spring Boot Admin. This however, required some
 * manual operations where the registered OAuth2AuthorizedClientManager
 * configured entries can be queries and the client_credential flow one
 * is retrieved. This is why the KeycloakOAuth2AuthorizedClientProvider
 * uses the defined OAuth2AuthorizedClientManager and picks the appropriate
 * client based on its registration ID.
 *
 * @author Nikolaos Vastardis (email: Nikolaos.Vastardis@gla-rad.org)
 */
@Component
public class KeycloakOAuth2AuthorizedClientProvider {

    /**
     * The default application name.
     */
    @Value("${spring.application.name:eureka}")
    private String appName;

    /**
     * The OAuth2 Authorised Client Manager.
     */
    @Autowired
    private OAuth2AuthorizedClientManager manager;

    /**
     * This function allows the service to access the authorised client that
     * uses the client credential flow and generate access tokens on demand.
     *
     * @return the authorised client that uses the client credential flow
     */
    public OAuth2AuthorizedClient getClient() {
        return manager.authorize(OAuth2AuthorizeRequest
                .withClientRegistrationId("sba")
                .principal(new AnonymousAuthenticationToken("name", this.appName, AuthorityUtils.createAuthorityList("ROLE_ACTUATOR")))
                .build());
    }

}
