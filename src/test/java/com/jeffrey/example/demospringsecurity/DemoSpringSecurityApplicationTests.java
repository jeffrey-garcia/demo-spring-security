package com.jeffrey.example.demospringsecurity;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
public class DemoSpringSecurityApplicationTests {

    @Test
    public void test1() {
        final PasswordEncoder encoder = new BCryptPasswordEncoder();

        String encodedPassword = encoder.encode("password");
        Assert.assertTrue(encoder.matches("password", encodedPassword));

    }

}
