package com.jeffrey.example.demospringsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

@EnableRedisHttpSession
@Configuration
public class WebSessionConfig<S extends Session> {

    @Autowired
    @Qualifier("webSecurityProperties")
    SecurityProperties securityProperties;

    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();

        /**
         * Allow browser to automatically send the session cookie even if
         * request is triggered from different domain
         * (i.e. frontend hosted in different domain)
         *
         * Frontend still couldn't access session cookie via javascript,
         * but this setting instruct browser to send the session cookie
         * anyway. So that CSRF protection is required with this relaxation.
         */
        serializer.setSameSite("");

        // configure the session cookie timeout in seconds
        serializer.setCookieMaxAge(securityProperties.loginSessionCookieTimeoutInSec);

        // configure the session cookie name
        serializer.setCookieName(securityProperties.loginSessionCookieName);

        // configure whether the session cookie will be transmitted only under https
        serializer.setUseSecureCookie(securityProperties.useSecureCookie);

        // session cookie must be http only and remains inaccessible by javascript to prevent XSS attack
        serializer.setUseHttpOnlyCookie(true);

        // all other settings remain as default

        return serializer;
    }

    @Bean
    @Qualifier("sessionRegistry")
    public SpringSessionBackedSessionRegistry<S> sessionRegistry(
            @Autowired FindByIndexNameSessionRepository<S> sessionRepository
    ) {
        return new SpringSessionBackedSessionRegistry<>(sessionRepository);
    }

}
