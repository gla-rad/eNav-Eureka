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

package org.grad.eNav.eureka.controllers;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The Custom Error Controller.
 *
 * In Springboot version 3.0.0 a bug causes services no not be able to
 * re-register with Eureka if the service restart. More information on the issue
 * can be found on the issue page:
 * <p/>
 * <a>https://github.com/spring-cloud/spring-cloud-netflix/issues/4145</a>
 * <p/>
 * To resulve this a temporary fix is to override the error mapping of the
 * service so that the clients get the correct response and re-register.
 *
 * @author Nikolaos Vastardis (email: Nikolaos.Vastardis@gla-rad.org)
 */
@RestController
class CustomErrorController implements ErrorController {

    /**
     * The Error Mapping.
     */
    private static final String ERROR_MAPPING = "/error";

    /**
     * The error request mapping that returns an empty NOT_FOUND response.
     *
     * @return An empty NOT_FOUND response.
     */
    @RequestMapping(ERROR_MAPPING)
    public ResponseEntity<Void> error() {
        return ResponseEntity.notFound()
                .build();
    }

}
