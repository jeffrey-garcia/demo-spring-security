package com.jeffrey.example.demospringsecurity.repository;

// This will be AUTO IMPLEMENTED by Spring into a Bean called userRepository
// CRUD refers Create, Read, Update, Delete

import com.jeffrey.example.demospringsecurity.model.Customer;
import org.springframework.data.repository.CrudRepository;

public interface CustomerRepository extends CrudRepository<Customer, Long> {

    Iterable<Customer> findByFirstName(String firstName);
    Iterable<Customer> findByLastName(String lastName);
    Iterable<Customer> findByFirstNameAndLastName(String firstName, String lastName);

}
