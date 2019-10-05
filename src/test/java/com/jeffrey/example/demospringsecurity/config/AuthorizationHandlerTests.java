package com.jeffrey.example.demospringsecurity.config;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class AuthorizationHandlerTests {

    @Mock
    AnonymousAuthenticationToken anonymous;

    @Mock
    UsernamePasswordAuthenticationToken user;

    @InjectMocks
    AuthorizationHandler authorizationHandler;

    @Before
    public void setup() {
//        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void verifyAllAccess_Anonymous() {
        when(anonymous.isAuthenticated()).thenReturn(true);
        Assert.assertFalse(authorizationHandler.hasAccess(anonymous));
        verify(anonymous, times(1)).isAuthenticated();
    }

    @Test
    public void verifyDisableAllAccess_Anonymous() {
        when(anonymous.isAuthenticated()).thenReturn(true);
        authorizationHandler.disableAllAccess();
        Assert.assertFalse(authorizationHandler.hasAccess(anonymous));
        verify(anonymous, times(1)).isAuthenticated();
    }

    @Test
    public void verifyAllAccess_User_NotLogin() {
        when(user.isAuthenticated()).thenReturn(false);
        Assert.assertFalse(authorizationHandler.hasAccess(user));
        verify(user, times(1)).isAuthenticated();
    }

    @Test
    public void verifyAllAccess_User_Login() {
        when(user.isAuthenticated()).thenReturn(true);
        Assert.assertTrue(authorizationHandler.hasAccess(user));
        verify(user, times(1)).isAuthenticated();
    }

    @Test
    public void verifyDisableAllAccess_User_NotLogin() {
        when(user.isAuthenticated()).thenReturn(false);
        authorizationHandler.disableAllAccess();
        Assert.assertFalse(authorizationHandler.hasAccess(user));
        verify(user, times(1)).isAuthenticated();
    }

    @Test
    public void verifyDisableAllAccess_User_Login() {
        when(user.isAuthenticated()).thenReturn(true);
        authorizationHandler.disableAllAccess();
        Assert.assertFalse(authorizationHandler.hasAccess(user));
        verify(user, times(1)).isAuthenticated();
    }

}
