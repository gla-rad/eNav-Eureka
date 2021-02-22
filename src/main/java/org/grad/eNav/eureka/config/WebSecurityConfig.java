/*
 * Copyright (c) 2021 GLA UK Research and Development Directive
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.grad.eNav.eureka.config;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.util.UUID;

/**
 * The Web Security Configuration.
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter  {

    /**
     * The Administration Service Properties
     */
    private final AdminServerProperties adminServerProperties;

    /**
     * The Configuration Constuctor
     *
     * @param adminServerProperties     The admin service properties
     */
    public WebSecurityConfig(AdminServerProperties adminServerProperties) {
        this.adminServerProperties = adminServerProperties;
    }

    /**
     * The HTTP security configuration.
     * <p>
     * For now this will allow all requests to the eureka micro-service admin
     * and config endpoints without any authorisation requirements. It also
     * sets up the login and logout operations.
     *
     * @param httpSecurity              The HTTP security
     * @throws Exception Exception thrown while configuring the security
     */
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setTargetUrlParameter("redirectTo");
        successHandler.setDefaultTargetUrl(this.adminServerProperties.getContextPath() + "/");

        httpSecurity
                .csrf().ignoringAntMatchers("/eureka/**", "/admin/**", "/config/**")
                .and()
                .authorizeRequests()
                .antMatchers(this.adminServerProperties.getContextPath() + "/assets/**").permitAll()
                .antMatchers(this.adminServerProperties.getContextPath() + "/login").permitAll()
                .antMatchers(
                        "/webjars/**",      //bootstrap
                        "/js/**", 						//js files
                        "/css/**", 						//css files
                        "/favicon.ico",                 //the favicon
                        "/actuator",                    //spring health actuator
                        "/actuator/**"                   //spring health actuator
                ).permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage(this.adminServerProperties.getContextPath() + "/login")
                .successHandler(successHandler)
                .and()
                .logout()
                .logoutUrl(this.adminServerProperties.getContextPath() + "/logout")
                .and()
                .httpBasic()
                .and()
                .rememberMe()
                .key(UUID.randomUUID().toString())
                .tokenValiditySeconds(1209600);
    }

}
