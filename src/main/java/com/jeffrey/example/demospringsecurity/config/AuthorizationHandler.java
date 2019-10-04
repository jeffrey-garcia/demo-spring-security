package com.jeffrey.example.demospringsecurity.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class AuthorizationHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationHandler.class);

    private volatile boolean disableAllAccess = false;

    public boolean hasAccess(Authentication authentication) {
        boolean isAnonymous = (authentication instanceof AnonymousAuthenticationToken);
        LOGGER.debug("has user authenticated? :{}", !isAnonymous);
        LOGGER.debug("all access disabled? :{}", disableAllAccess);
        return (!isAnonymous && !disableAllAccess);
    }

    public void disableAllAccess() {
        if (disableAllAccess) return;
        LOGGER.debug("Disabling all controllers access...");
        disableAllAccess = true;
    }
}