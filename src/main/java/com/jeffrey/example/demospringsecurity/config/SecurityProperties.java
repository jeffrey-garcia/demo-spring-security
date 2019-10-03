package com.jeffrey.example.demospringsecurity.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@RefreshScope
@Configuration
public class SecurityProperties {

    @Value("${cors.allowed.origins}")
    public String[] corsAllowedOrigins;

    @Value("${csrf.cookie.root.domain}")
    public String csrfCookiesRootDomain;

    @Value("${login.complete.redirect.url}")
    public String loginCompleteRedirectUrl;

    @Value("${login.session.cookie.timeoutInSec}")
    public int loginSessionCookieTimeoutInSec;

    @Value("${login.session.cookie.name}")
    public String loginSessionCookieName;

    @Bean
    @Qualifier("webSecurityProperties")
    SecurityProperties webSecurityProperties() {
        return new SecurityProperties();
    }

}
