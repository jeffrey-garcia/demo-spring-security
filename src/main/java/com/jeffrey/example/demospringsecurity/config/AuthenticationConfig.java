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
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Collections;

@Configuration
public class AuthenticationConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationConfig.class);

    public static final String USER_TOKEN = "userToken";

    @Autowired
    @Qualifier("webSecurityProperties")
    SecurityProperties securityProperties;

    @Autowired
    @Qualifier("csrfTokenRepository")
    CsrfTokenRepository csrfTokenRepository;

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
                    bindUserToSession(username);
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
                        bindUserToSession(username);
                        return new UsernamePasswordAuthenticationToken(username, password, Collections.emptyList());
                    }
                } catch (UsernameNotFoundException e) {
                    LOGGER.error(e.getMessage(), e);
                }

                throw new BadCredentialsException("Authentication failed.");
            }

            private void bindUserToSession(final String username) {
                HttpServletRequest httpServletRequest = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
                LOGGER.debug("bindUserToSession url: {}, method: {}", httpServletRequest.getRequestURI(), httpServletRequest.getMethod());

                HttpSession currentSession = httpServletRequest.getSession(false);
                if (currentSession != null) {
                    LOGGER.debug("previous session already exist: {}", currentSession.getId());
                } else {
                    LOGGER.debug("creating new session...");
                    currentSession = httpServletRequest.getSession();
                }
                currentSession.setAttribute(USER_TOKEN, username);

                LOGGER.debug("current session id: {}", currentSession.getId());
                LOGGER.debug("current session creation time: {}", currentSession.getCreationTime());
                LOGGER.debug("current session attribute: {}", currentSession.getAttribute(USER_TOKEN));
                LOGGER.debug("current session is newly generated? {}", currentSession.isNew());
            }
        };
    }

    @Bean
    @Qualifier("authenticationSuccessHandler")
    AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(
                    HttpServletRequest httpServletRequest,
                    HttpServletResponse httpServletResponse,
                    Authentication authentication) throws IOException, ServletException
            {
                LOGGER.debug("onAuthenticationSuccess url: {}, method: {}", httpServletRequest.getRequestURI(), httpServletRequest.getMethod());

                // new session should have been created after authentication success
                HttpSession currentSession = httpServletRequest.getSession(false);
                Assert.notNull(currentSession, "current session should be null!");

                // validate session-fixation attack
                // previous session's data should have been migrated to the new session
                Assert.isTrue(currentSession.getAttribute(USER_TOKEN).equals(authentication.getName()),
                        "session attribute is not replicated!");

                LOGGER.debug("current session id: {}", currentSession.getId());
                LOGGER.debug("current session creation time: {}", currentSession.getCreationTime());
                LOGGER.debug("current session userId attribute: {}", currentSession.getAttribute(USER_TOKEN));
                LOGGER.debug("current session is newly generated? {}", currentSession.isNew());

                // pass the CSRF token via cookie to front-end
                CsrfToken csrfToken = csrfTokenRepository.loadToken(httpServletRequest);
                Cookie csrfCookie = CsrfConfig.createCsrfCookie(csrfToken, httpServletRequest.getContextPath(), securityProperties.csrfCookiesRootDomain);
                httpServletResponse.addCookie(csrfCookie);

                RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
                redirectStrategy.sendRedirect(
                        httpServletRequest,
                        httpServletResponse,
                        securityProperties.loginCompleteRedirectUrl
                );
            }
        };
    }
}


