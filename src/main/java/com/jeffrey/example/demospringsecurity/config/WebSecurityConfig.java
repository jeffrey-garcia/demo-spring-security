package com.jeffrey.example.demospringsecurity.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private final Logger LOGGER = LoggerFactory.getLogger(WebSecurityConfig.class);

    @Autowired
    @Qualifier("webSecurityProperties")
    SecurityProperties securityProperties;

    @Autowired
    @Qualifier("sessionRegistry")
    SpringSessionBackedSessionRegistry sessionRegistry;

    @Autowired
    @Qualifier("csrfTokenRepository")
    CsrfTokenRepository csrfTokenRepository;

    @Autowired
    @Qualifier("csrfFilter")
    OncePerRequestFilter csrfFilter;

    @Autowired
    @Qualifier("passwordEncoder")
    PasswordEncoder encoder;

    @Autowired
    @Qualifier("authenticationProvider")
    AuthenticationProvider authenticationProvider;

    @Autowired
    @Qualifier("authenticationSuccessHandler")
    AuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    @Qualifier("userDetailsService")
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers(
                        // declare the public endpoint before the private if the private domains is a superset of the public
                        "/actuator*/**"
                ).permitAll()
                .antMatchers(
                        "/**"
                ).access("@authorizationHandler.hasAccess(authentication)")
                .anyRequest().authenticated();

        http
            .formLogin() // auto redirect default spring login page and won't return 401/403
                .permitAll()
                .successHandler(authenticationSuccessHandler);

        http
            .logout()
                .deleteCookies(securityProperties.loginSessionCookieName)
                .permitAll();

        http
            // enable CORS
            .cors();

        http
            .csrf()
                // disable csrf for actuator's endpoint (POST/PUT/DELETE) otherwise they will be blocked
                .ignoringAntMatchers("/login", "/actuator*/**")
                .csrfTokenRepository(csrfTokenRepository) // defines a repository where tokens are stored
                .and()
                .addFilterAfter(csrfFilter, CsrfFilter.class); // CSRF filter to add the cookie

        http
            // define HTTP session related functionality
            .sessionManagement()
            // session-fixation attack protection
            // create a new session and copy all existing session attributes to the new session upon re-authentication
            .sessionFixation().migrateSession()
            // restrictions on how many sessions an authenticated user may have open concurrently
            .maximumSessions(securityProperties.maxConcurrentSessionsPerUser)
            .sessionRegistry(sessionRegistry);
    }

    @Override
    public void configure(AuthenticationManagerBuilder authMgrBuilder) throws Exception {
        authMgrBuilder.authenticationProvider(authenticationProvider);
    }

    @Override
    public UserDetailsService userDetailsService() {
        return this.userDetailsService;
    }
}