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

package org.grad.eNav.eureka;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;

import static org.mockito.Mockito.mock;

/**
 * This is a test only configuration that will get activated when the "test"
 * profile is active.
 *
 * @author Nikolaos Vastardis (email: Nikolaos.Vastardis@gla-rad.org)
 */
@TestConfiguration
public class TestingConfiguration {

    /**
     * The OAuth2 Authorised Client Manager mock.
     *
     * @return  the OAuth2 Authorised Client Manager
     */
    @Bean
    OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager() {
        return mock(OAuth2AuthorizedClientManager.class);
    }

}
