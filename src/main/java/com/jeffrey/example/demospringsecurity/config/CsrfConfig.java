package com.jeffrey.example.demospringsecurity.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
public class CsrfConfig {
    private Logger LOGGER = LoggerFactory.getLogger(CsrfConfig.class);

    public static final String COOKIE_NAME = "XSRF-TOKEN";
    public static final String HEADER_NAME = "X-CSRF-TOKEN";
    public static final String PARAM_NAME = "_csrf";
    public static final String DIVERSIFIER = "_csrf_diversifier";

    @Autowired
    @Qualifier("webSecurityProperties")
    SecurityProperties securityProperties;

    @Bean
    @Qualifier("csrfTokenRepository")
    public CsrfTokenRepository csrfTokenRepository() {
//        return new CsrfTokenRepository() {
//            /**
//             * By default the CookieCsrfTokenRepository will write to a cookie named XSRF-TOKEN
//             * and read it from a header named X-XSRF-TOKEN or the HTTP parameter _csrf.
//             *
//             * cookieHttpOnly=false is necessary to allow JavaScript (i.e. Angular) to read it.
//             * If you do not need the ability to read the cookie with JavaScript directly, it
//             * is recommended to omit cookieHttpOnly=false to improve security.
//             */
//            private final CookieCsrfTokenRepository repository = new CookieCsrfTokenRepository().withHttpOnlyFalse();
//
//            @Override
//            public CsrfToken generateToken(HttpServletRequest httpServletRequest) {
//                // Apply custom token generation logic here
//                CsrfToken csrfToken = new DefaultCsrfToken(
//                        HEADER_NAME,
//                        PARAM_NAME,
//                        UUID.randomUUID().toString());
//
//                LOGGER.debug("generate csrf token url: {}, method: {}", httpServletRequest.getRequestURI(), httpServletRequest.getMethod());
//                LOGGER.debug("generate csrf token: {}", csrfToken.getToken());
//                return csrfToken;
//            }
//
//            @Override
//            public void saveToken(CsrfToken csrfToken, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
//                if (csrfToken == null) return;
//
//                LOGGER.debug("save csrf token url: {}, method: {}", httpServletRequest.getRequestURI(), httpServletRequest.getMethod());
//                LOGGER.debug("save csrf token: {}", csrfToken==null? "":csrfToken.getToken());
//
//
//                repository.saveToken(csrfToken, httpServletRequest, httpServletResponse);
//            }
//
//            @Override
//            public CsrfToken loadToken(HttpServletRequest httpServletRequest) {
//                CsrfToken csrfToken = repository.loadToken(httpServletRequest);
//                LOGGER.debug("load csrf token url: {}, method: {}", httpServletRequest.getRequestURI(), httpServletRequest.getMethod());
//                LOGGER.debug("load csrf token: {}", csrfToken==null? null:csrfToken.getToken());
//                return csrfToken;
//            }
//        };
        return new CsrfTokenRepository() {
            private final HttpSessionCsrfTokenRepository csrfTokenRepository = new HttpSessionCsrfTokenRepository();

            @Override
            public CsrfToken generateToken(HttpServletRequest httpServletRequest) {
                CsrfToken newToken = csrfTokenRepository.generateToken(httpServletRequest);

                HttpSession session = httpServletRequest.getSession(false);
                if (session == null || session.getAttribute(DIVERSIFIER) == null) {
                    LOGGER.debug("csrf token generated: {}", newToken.getToken());
                    return newToken;
                } else {
                    // diversify the CSRF token with a user specific variable at run-time, protect against CSRF token compromised at front-end
                    // unless the attacker also exploit the diversifier, otherwise he won't be able to pass the CSRF token validation logic
                    Object userToken = session.getAttribute(DIVERSIFIER);
                    CsrfToken diversifiedCsrfToken = new DefaultCsrfToken(
                            newToken.getHeaderName(),
                            newToken.getParameterName(),
                            newToken.getToken().concat((String) userToken)
                    );
                    LOGGER.debug("csrf salted token generated: {}", diversifiedCsrfToken.getToken());
                    return diversifiedCsrfToken;
                }
            }

            @Override
            public void saveToken(CsrfToken csrfToken, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
                csrfTokenRepository.saveToken(csrfToken, httpServletRequest, httpServletResponse);
            }

            @Override
            public CsrfToken loadToken(HttpServletRequest httpServletRequest) {
                return csrfTokenRepository.loadToken(httpServletRequest);
            }
        };
    }

    @Bean
    @Qualifier("csrfFilter")
    public OncePerRequestFilter csrfFilter(CsrfTokenRepository repository) {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(
                    HttpServletRequest httpServletRequest,
                    HttpServletResponse httpServletResponse,
                    FilterChain filterChain) throws ServletException, IOException
            {
                // pass the CSRF token via cookie to front-end
                CsrfToken csrfToken = repository.loadToken(httpServletRequest);

                LOGGER.debug("doFilterInternal url: {}, method: {}", httpServletRequest.getRequestURI(), httpServletRequest.getMethod());
                LOGGER.debug("doFilterInternal csrf token: {}", csrfToken==null? null:csrfToken.getToken());

                Cookie csrfCookie = CsrfConfig.createCsrfCookie(csrfToken, httpServletRequest.getContextPath(), securityProperties.csrfCookiesRootDomain);

                httpServletResponse.addCookie(csrfCookie);

                filterChain.doFilter(httpServletRequest, httpServletResponse);
            }
        };
    }

    public static Cookie createCsrfCookie(
            CsrfToken csrfToken,
            String cookiePath,
            String cookiesRootDomain) {
        Cookie csrfCookie = new Cookie(COOKIE_NAME.toString(), csrfToken==null? "":csrfToken.getToken());

        // assign the cookie domain
        csrfCookie.setDomain(cookiesRootDomain);
        if (!"localhost".equalsIgnoreCase(cookiesRootDomain))
        {
            csrfCookie.setSecure(true);
        }

        String contextPath = cookiePath;
        csrfCookie.setPath(contextPath.length() > 0 ? contextPath:"/");

        csrfCookie.setHttpOnly(false);
        return csrfCookie;
    }
}


