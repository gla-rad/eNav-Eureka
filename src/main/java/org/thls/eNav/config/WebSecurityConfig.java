package org.thls.eNav.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter  {

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                //disable csrf
                .csrf().disable()
                .authorizeRequests()
                // dont authenticate these requests
                .antMatchers(
                        "/webjars/**",      //bootstrap
                        "/js/**",                       //js files
                        "/css/**",                      //css files
                        "/login",                       //the login page
                        "/actuator/health"              //spring health actuator
                ).permitAll()
                //Other requests need to be authenticated
                .anyRequest().authenticated()
                //set the login page for api users
                .and().formLogin()
                //.loginPage("/login")
                .permitAll();
    }

}
