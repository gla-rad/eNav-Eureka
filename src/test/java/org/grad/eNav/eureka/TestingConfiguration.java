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

import com.netflix.appinfo.ApplicationInfoManager;
import com.netflix.discovery.EurekaClient;
import com.netflix.discovery.EurekaClientConfig;
import com.netflix.eureka.EurekaServerContext;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

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
     * The Application Infor Manager mock.
     *
     * @return  the Application Info Manager
     */
    @Bean
    public ApplicationInfoManager applicationInfoManager() {
        return mock(ApplicationInfoManager.class);
    }

    /**
     * The Eureka Client Config mock.
     *
     * @return  the Eureka Client Config
     */
    @Bean
    EurekaClientConfig eurekaClientConfig() {
        return mock(EurekaClientConfig.class);
    }

    /**
     * The Eureka Client mock.
     *
     * @return  the Eureka Client
     */
    @Bean
    EurekaClient eurekaClient() {
        return mock(EurekaClient.class);
    }

    /**
     * The Eureka Server Context mock.
     *
     * @return  the Eureka Server Context
     */
    @Bean
    EurekaServerContext eurekaServerContext() {
        return mock(EurekaServerContext.class);
    }

}