package com.jeffrey.example.demospringsecurity.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;

@Configuration
public class CsrfConfig {
    private Logger LOGGER = LoggerFactory.getLogger(CsrfConfig.class);

    @Autowired
    @Qualifier("webSecurityProperties")
    SecurityProperties securityProperties;

    @Bean
    @Qualifier("csrfTokenRepository")
    public CsrfTokenRepository csrfTokenRepository() {
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
                // CsrfToken csrfToken = repository.generateToken(httpServletRequest);

                // Apply custom token generation logic here
                CsrfToken csrfToken = new DefaultCsrfToken(
                        CSRF.HEADER_NAME.toString(),
                        CSRF.PARAM_NAME.toString(),
                        UUID.randomUUID().toString());

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
                repository.saveToken(csrfToken, httpServletRequest, httpServletResponse);
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

    @Bean
    @Qualifier("csrfFilter")
    public OncePerRequestFilter csrfFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
                CsrfToken csrfToken = (CsrfToken) httpServletRequest.getAttribute(CsrfToken.class.getName());
                LOGGER.debug("doFilterInternal url: {}, method: {}", httpServletRequest.getRequestURI(), httpServletRequest.getMethod());
                LOGGER.debug("doFilterInternal token: {}", csrfToken==null? null:csrfToken.getToken());

//                if (csrfToken != null) {
//                    Cookie cookie = WebUtils.getCookie(httpServletRequest, CSRF.COOKIE_NAME.toString());
//                    String token = csrfToken.getToken();
//
//                    if (cookie == null || token != null && !token.equals(cookie.getValue())) {
//                        cookie = new Cookie(CSRF.COOKIE_NAME.toString(), token);
//
//                        // assign the cookie domain
//                        cookie.setDomain(securityProperties.csrfCookiesRootDomain);
//                        if (!"localhost".equalsIgnoreCase(securityProperties.csrfCookiesRootDomain))
//                        {
//                            cookie.setSecure(true);
//                        }
//
//                        cookie.setPath("/");
//                        cookie.setHttpOnly(false);
//
//                        httpServletResponse.addCookie(cookie);
//                    }
//                }

                filterChain.doFilter(httpServletRequest, httpServletResponse);
            }
        };
    }

}
