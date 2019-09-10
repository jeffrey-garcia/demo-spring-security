package com.jeffrey.example.demospringsecurity.service;

import com.jeffrey.example.demospringsecurity.model.Customer;
import com.jeffrey.example.demospringsecurity.repository.CustomerRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class CustomerService {
    private static final Logger LOGGER = LoggerFactory.getLogger(CustomerService.class);

    private AtomicLong counter = new AtomicLong();

    @Autowired
    CustomerRepository customerRepository;

    @Autowired
    Environment environment;

    public Iterable<Customer> getAllCustomers() {
        return customerRepository.findAll();
    }

    public Customer addCustomer(final Customer customer) throws RuntimeException {
        return customerRepository.save(customer);
    }

    public Iterable<Customer> addCustomers(final List<Customer> customers) throws RuntimeException {
        return customerRepository.saveAll(customers);
    }

}
