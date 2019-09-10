package com.jeffrey.example.demospringsecurity.controller;

import com.jeffrey.example.demospringsecurity.model.Customer;
import com.jeffrey.example.demospringsecurity.service.CustomerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class MainController {
    private static final Logger LOGGER = LoggerFactory.getLogger(MainController.class);

    @Autowired
    private CustomerService customerService;

    /**
     * curl "http://localhost:8080/customers" -i -X GET
     */
    @GetMapping(path="/customers")
    public @ResponseBody Iterable<Customer> getAllCustomers() {
        LOGGER.debug("getAllCustomers");
        return customerService.getAllCustomers();
    }

    /**
     * curl "http://localhost:8080/customer?firstName=J&lastName=G" -i -X GET
     */
    @GetMapping(path="/customer")
    public @ResponseBody Customer createCustomerFromQueryString(@RequestParam String firstName, @RequestParam String lastName) {
        LOGGER.debug("createCustomerFromQueryString");
        Customer customer = new Customer(firstName, lastName);
        return customerService.addCustomer(customer);
    }

    /**
     * curl "http://localhost:8080/customer" -i -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "firstName=S&lastName=R"
     */
    @PostMapping(path="/customer", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public @ResponseBody Customer createCustomerFormPost(@RequestBody MultiValueMap<String, String> formData) {
        LOGGER.debug("createCustomerFormPost");

        String firstName = formData.get("firstName").get(0);
        String lastName = formData.get("lastName").get(0);

        Customer customer = new Customer(firstName, lastName);
        return customerService.addCustomer(customer);
    }

    /**
     * curl 'http://localhost:8080/customers' -i -X POST -H "Content-Type: application/json" -d '[{"firstName":"","lastName":"S"}]'
     */
    @PostMapping(path="/customers")
    public @ResponseBody Iterable<Customer> createCustomerFromJsonBody(@RequestBody List<Customer> customers) {
        LOGGER.debug("createCustomerFromJsonBody");
        return customerService.addCustomers(customers);
    }

}
