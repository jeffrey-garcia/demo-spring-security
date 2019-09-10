package com.jeffrey.example.demospringsecurity.config;

public enum CSRF {
    COOKIE_NAME("XSRF-TOKEN"),
    HEADER_NAME("X-XSRF-TOKEN");

    private String name;

    CSRF(String name) {
        this.name = name;
    }

    public String toString() {
        return this.name;
    }
}