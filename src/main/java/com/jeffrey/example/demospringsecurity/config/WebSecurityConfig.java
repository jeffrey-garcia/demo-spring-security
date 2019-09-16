package com.jeffrey.example.demospringsecurity.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private Logger LOGGER = LoggerFactory.getLogger(WebSecurityConfig.class);

    @Autowired
    @Qualifier("webSecurityProperties")
    SecurityProperties securityProperties;

    @Autowired
    @Qualifier("csrfTokenRepository")
    CsrfTokenRepository csrfTokenRepository;

    @Autowired
    @Qualifier("csrfFilter")
    OncePerRequestFilter csrfFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers(
                        "/**"
                ).access("@authorizationHandler.hasAccess(authentication)")
                .antMatchers(
                        "/actuator/**"
                ).permitAll()
                .anyRequest().authenticated()
        .and()
            .formLogin() // auto redirect default spring login page and won't return 401/403
                .permitAll()
                .successHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
                    redirectStrategy.sendRedirect(
                            httpServletRequest,
                            httpServletResponse,
                            securityProperties.loginCompleteRedirectUrl
                    );
                })
        .and()
            .logout()
                .permitAll()
        .and()
            .cors() // enable CORS
        .and()
            .csrf()
                // disable csrf for actuator's endpoint (POST/PUT/DELETE) otherwise they will be blocked
                .ignoringAntMatchers("/login", "/actuator/**")
                .csrfTokenRepository(csrfTokenRepository) // defines a repository where tokens are stored
                .and()
                .addFilterAfter(csrfFilter, CsrfFilter.class); // CSRF filter to add the cookie
    }

    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        UserDetails user =
                User.withDefaultPasswordEncoder()
                        .username("user")
                        .password("password")
                        .roles("USER")
                        .build();

        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    @Qualifier("authorizationHandler")
    public AuthorizationHandler authorizationHandler() {
        return new AuthorizationHandler() {
            private boolean disableAllAccess = false;

            @Override
            public boolean hasAccess(Authentication authentication) {
                boolean isAnonymous = (authentication instanceof AnonymousAuthenticationToken);
                LOGGER.debug("has user authenticated? :{}", !isAnonymous);
                return (!isAnonymous && !disableAllAccess);
            }

            @Override
            public void disableAllAccess() {
                LOGGER.debug("Disabling all controllers access...");
                disableAllAccess = true;
            }
        };
    }

    interface AuthorizationHandler {
        boolean hasAccess(Authentication authentication);
        void disableAllAccess();
    }

}