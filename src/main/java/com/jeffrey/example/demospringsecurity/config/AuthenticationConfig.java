package com.jeffrey.example.demospringsecurity.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Collections;

@Configuration
public class AuthenticationConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationConfig.class);

    @Bean
    @Qualifier("passwordEncoder")
    PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Qualifier("userDetailsService")
    UserDetailsService userDetailsService(@Autowired PasswordEncoder encoder) {
        UserDetails user = User.builder()
                            .username("user")
                            .password(encoder.encode("password"))
                            .roles("USER")
                            .build();

        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    @Qualifier("authenticationProvider")
    AuthenticationProvider authenticationProvider(
            @Autowired UserDetailsService userDetailsService,
            @Autowired PasswordEncoder encoder
    ) {
        return new AuthenticationProvider() {
            @Override
            public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
                final String username = authentication.getName();
                final String password = authentication.getCredentials().toString();
                return verifyCredentialExternal(username, password);
            }

            @Override
            public boolean supports(Class<?> authClass) {
                return authClass.equals(UsernamePasswordAuthenticationToken.class);
            }

            private UsernamePasswordAuthenticationToken verifyCredentialExternal(final String username, final String password) {
                // demonstrate external identity provider's custom login validation logic
                if ("user1".equals(username) && "password1".equals(password)) {
                    loadHttpSession();
                    return new UsernamePasswordAuthenticationToken(username, password, Collections.emptyList());

                } else {
                    LOGGER.warn("Credential verification failed with external system, falling back to in-memory credential verification");
                    // fallback to in-memory authentication providers if login fail with custom authentication provider
                    return verifyCredentialInMemory(username, password);
                }
            }

            private UsernamePasswordAuthenticationToken verifyCredentialInMemory(final String username, final String password) {
                try {
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    if (userDetails.getPassword() != null && encoder.matches(password, userDetails.getPassword())) {
                        loadHttpSession();
                        return new UsernamePasswordAuthenticationToken(username, password, Collections.emptyList());
                    }
                } catch (UsernameNotFoundException e) {
                    LOGGER.error(e.getMessage(), e);
                }

                throw new BadCredentialsException("Authentication failed.");
            }

            private HttpSession loadHttpSession() {
                HttpServletRequest httpServletRequest = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
                LOGGER.debug("authentication provider url: {}, method: {}", httpServletRequest.getRequestURI(), httpServletRequest.getMethod());

                HttpSession currentSession = httpServletRequest.getSession(false);
                if (currentSession != null) {
                    LOGGER.debug("previous session already exist: {}", currentSession.getId());
                    // validate session-fixation-protection, if no error is thrown, session is migrated
                    Assert.isTrue(currentSession.getAttribute("testing").equals("123"), "session attribute is not replicated!");
                } else {
                    LOGGER.debug("creating new session...");
                    currentSession = httpServletRequest.getSession();
                    currentSession.setAttribute("testing", "123");
                }

                LOGGER.debug("current session id: {}", currentSession.getId());
                LOGGER.debug("current session creation time: {}", currentSession.getCreationTime());
                LOGGER.debug("current session attribute: {}", currentSession.getAttribute("testing"));
                LOGGER.debug("current session is newly generated? {}", currentSession.isNew());

                return currentSession;
            }
        };
    }
}


