package com.jeffrey.example.demospringsecurity.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
public class Customer {

    @JsonProperty
    @Id
    @GeneratedValue(strategy= GenerationType.AUTO)
    private long id;

    @JsonProperty
    private String firstName;

    @JsonProperty
    private String lastName;

    public Customer() {}

    public Customer(final String firstName, final String lastName) {
        this.firstName = firstName;
        this.lastName = lastName;
    }

//    public void setId(final long id) {
//        this.id = id;
//    }

}
