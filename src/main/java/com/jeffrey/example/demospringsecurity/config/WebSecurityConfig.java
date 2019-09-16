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
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private Logger LOGGER = LoggerFactory.getLogger(WebSecurityConfig.class);

    @Autowired
    @Qualifier("webSecurityProperties")
    SecurityProperties securityProperties;

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
                .csrfTokenRepository(csrfTokenRepository()) // defines a repository where tokens are stored
                .and()
                .addFilterAfter(csrfFilter(), CsrfFilter.class); // CSRF filter to add the cookie
    }

    private CsrfTokenRepository csrfTokenRepository() {
        return new CsrfTokenRepository() {
            /**
             * By default the CookieCsrfTokenRepository will write to a cookie named XSRF-TOKEN
             * and read it from a header named X-XSRF-TOKEN or the HTTP parameter _csrf.
             *
             * cookieHttpOnly=false is necessary to allow JavaScript (i.e. Angular) to read it.
             * If you do not need the ability to read the cookie with JavaScript directly, it
             * is recommended to omit cookieHttpOnly=false to improve security.
             */
            private final CookieCsrfTokenRepository repository = new CookieCsrfTokenRepository().withHttpOnlyFalse();

            @Override
            public CsrfToken generateToken(HttpServletRequest httpServletRequest) {
                CsrfToken csrfToken = repository.generateToken(httpServletRequest);
                LOGGER.debug("generate token url: {}, method: {}", httpServletRequest.getRequestURI(), httpServletRequest.getMethod());
                LOGGER.debug("generate token: {}", csrfToken.getToken());
                return csrfToken;
            }

            @Override
            public void saveToken(CsrfToken csrfToken, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
                if (csrfToken == null) return;

                LOGGER.debug("save token url: {}, method: {}", httpServletRequest.getRequestURI(), httpServletRequest.getMethod());
                LOGGER.debug("save token: {}", csrfToken==null? "":csrfToken.getToken());

                Cookie cookie = new Cookie(CSRF.COOKIE_NAME.toString(), csrfToken==null? "":csrfToken.getToken());

                // assign the cookie domain
                cookie.setDomain(securityProperties.csrfCookiesRootDomain);
                if (!"localhost".equalsIgnoreCase(securityProperties.csrfCookiesRootDomain))
                {
                    cookie.setSecure(true);
                }

                if (!StringUtils.isEmpty(repository.getCookiePath())) {
                    cookie.setPath(repository.getCookiePath());
                } else {
                    String contextPath = httpServletRequest.getContextPath();
                    cookie.setPath(contextPath.length() > 0 ? contextPath:"/");
                }

                cookie.setHttpOnly(false);
                httpServletResponse.addCookie(cookie);
            }

            @Override
            public CsrfToken loadToken(HttpServletRequest httpServletRequest) {
                CsrfToken csrfToken = repository.loadToken(httpServletRequest);
                LOGGER.debug("load token url: {}, method: {}", httpServletRequest.getRequestURI(), httpServletRequest.getMethod());
                LOGGER.debug("load token: {}", csrfToken==null? null:csrfToken.getToken());
                return csrfToken;
            }
        };
    }

    private OncePerRequestFilter csrfFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
                CsrfToken csrfToken = (CsrfToken) httpServletRequest.getAttribute(CsrfToken.class.getName());
                LOGGER.debug("doFilterInternal url: {}, method: {}", httpServletRequest.getRequestURI(), httpServletRequest.getMethod());
                LOGGER.debug("doFilterInternal token: {}", csrfToken==null? null:csrfToken.getToken());

                if (csrfToken != null) {
                    Cookie cookie = WebUtils.getCookie(httpServletRequest, CSRF.COOKIE_NAME.toString());
                    String token = csrfToken.getToken();

                    if (cookie == null || token != null && !token.equals(cookie.getValue())) {
                        cookie = new Cookie(CSRF.COOKIE_NAME.toString(), token);

                        // assign the cookie domain
                        cookie.setDomain(securityProperties.csrfCookiesRootDomain);
                        if (!"localhost".equalsIgnoreCase(securityProperties.csrfCookiesRootDomain))
                        {
                            cookie.setSecure(true);
                        }

                        cookie.setPath("/");
                        cookie.setHttpOnly(false);
                        httpServletResponse.addCookie(cookie);
                    }
                }

                filterChain.doFilter(httpServletRequest, httpServletResponse);
            }
        };
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