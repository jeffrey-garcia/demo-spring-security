package com.jeffrey.example.demospringsecurity.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
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
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Collections;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig<S extends Session> extends WebSecurityConfigurerAdapter {
    private final Logger LOGGER = LoggerFactory.getLogger(WebSecurityConfig.class);

    private final PasswordEncoder encoder = new BCryptPasswordEncoder();

    @Autowired
    @Qualifier("webSecurityProperties")
    SecurityProperties securityProperties;

    @Autowired
    @Qualifier("csrfTokenRepository")
    CsrfTokenRepository csrfTokenRepository;

    @Autowired
    @Qualifier("csrfFilter")
    OncePerRequestFilter csrfFilter;

    @Autowired
    @Qualifier("authenticationProvider")
    AuthenticationProvider authenticationProvider;

    @Autowired FindByIndexNameSessionRepository<S> sessionRepository;

    @Autowired
    ObjectFactory<HttpSession> httpSessionFactory;

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
                .ignoringAntMatchers("/login", "/actuator*/**")
                .csrfTokenRepository(csrfTokenRepository) // defines a repository where tokens are stored
                .and()
                .addFilterAfter(csrfFilter, CsrfFilter.class); // CSRF filter to add the cookie

        http
            // define HTTP session related functionality
            .sessionManagement()
            // session-fixation protection attack protection
            // create a new session and copy all existing session attributes to the new session upon re-authentication
            .sessionFixation().migrateSession()
            // restrictions on how many sessions an authenticated user may have open concurrently
            .maximumSessions(securityProperties.maxConcurrentSessionsPerUser)
            .sessionRegistry(sessionRegistry());
    }

    @Bean
    public SpringSessionBackedSessionRegistry<S> sessionRegistry() {
        return new SpringSessionBackedSessionRegistry<>(this.sessionRepository);
    }

    @Bean
    @Qualifier("authenticationProvider")
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService) {
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
                    if (userDetails.getPassword()!=null && encoder.matches(password, userDetails.getPassword())) {
                        loadHttpSession();
                        return new UsernamePasswordAuthenticationToken(username, password, Collections.emptyList());
                    }
                } catch(UsernameNotFoundException e) {
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
                    currentSession.setAttribute("testing","123");
                }

                LOGGER.debug("current session id: {}", currentSession.getId());
                LOGGER.debug("current session creation time: {}", currentSession.getCreationTime());
                LOGGER.debug("current session attribute: {}", currentSession.getAttribute("testing"));
                LOGGER.debug("current session is newly generated? {}", currentSession.isNew());

                return currentSession;
            }
        };
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider);
    }

    @Bean
    @Qualifier("userDetailsService")
    @Override
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                            .username("user")
                            .password(encoder.encode("password"))
                            .roles("USER")
                            .build();

        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    @Qualifier("authorizationHandler")
    public AuthorizationHandler authorizationHandler() {
        return new AuthorizationHandler() {
            private volatile boolean disableAllAccess = false;

            @Override
            public boolean hasAccess(Authentication authentication) {
                boolean isAnonymous = (authentication instanceof AnonymousAuthenticationToken);
                LOGGER.debug("has user authenticated? :{}", !isAnonymous);
                LOGGER.debug("all access disabled? :{}", disableAllAccess);
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