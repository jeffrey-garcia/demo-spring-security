package com.jeffrey.example.demospringsecurity.config;

import com.google.common.collect.Lists;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
public class AuthorizationHandlerTests {

    AnonymousAuthenticationToken anonymous = new AnonymousAuthenticationToken(
            "key",
            "principal",
            Lists.newArrayList(new SimpleGrantedAuthority("role")));

    UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken(
            "principal",
            "credential",
            Lists.newArrayList(new SimpleGrantedAuthority("role")));

    AuthorizationHandler authorizationHandler = new AuthorizationHandler();

    @Before
    public void setup() { }

    @Test
    public void verifyAccess_Anonymous() {
        Assert.assertFalse(authorizationHandler.hasAccess(anonymous));
    }

    @Test
    public void verifyDisableAllAccess_Anonymous() {
        authorizationHandler.disableAllAccess();
        Assert.assertFalse(authorizationHandler.hasAccess(anonymous));
    }

    @Test
    public void verifyAllAccess_User_NotLogin() {
        user.setAuthenticated(false);
        Assert.assertFalse(authorizationHandler.hasAccess(user));
    }

    @Test
    public void verifyAllAccess_User_Login() {
        Assert.assertTrue(authorizationHandler.hasAccess(user));
    }

    @Test
    public void verifyDisableAllAccess_User_NotLogin() {
        user.setAuthenticated(false);
        authorizationHandler.disableAllAccess();
        Assert.assertFalse(authorizationHandler.hasAccess(user));
    }

    @Test
    public void verifyDisableAllAccess_User_Login() {
        user.setAuthenticated(false);
        authorizationHandler.disableAllAccess();
        Assert.assertFalse(authorizationHandler.hasAccess(user));
    }

}
