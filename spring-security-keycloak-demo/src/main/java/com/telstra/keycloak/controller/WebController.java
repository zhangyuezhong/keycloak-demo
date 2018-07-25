package com.telstra.keycloak.controller;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.telstra.keycloak.domain.data.Customer;

@Controller
public class WebController {

	@GetMapping(path = "/")
	public String index() {
		return "external";
	}

	@PreAuthorize("hasRole('user')")
	@GetMapping(path = "/customers")
	public String customers(Principal principal, Model model) {
		Iterable<Customer> customers = this.getCustomers();
		model.addAttribute("customers", customers);
		model.addAttribute("username", principal.getName());

		Authentication token = (Authentication) principal;
		token.getAuthorities().forEach(System.out::println);
		System.out.println(principal.getClass().getCanonicalName());

		return "customers";
	}

	// add customers for demonstration
	public List<Customer> getCustomers() {
		List<Customer> list = new ArrayList<Customer>();
		Customer customer1 = new Customer();
		customer1.setAddress("1111 foo blvd");
		customer1.setName("Foo Industries");
		customer1.setServiceRendered("Important services");
		list.add(customer1);

		Customer customer2 = new Customer();
		customer2.setAddress("2222 bar street");
		customer2.setName("Bar LLP");
		customer2.setServiceRendered("Important services");
		list.add(customer2);

		Customer customer3 = new Customer();
		customer3.setAddress("33 main street");
		customer3.setName("Big LLC");
		customer3.setServiceRendered("Important services");
		list.add(customer3);
		return list;
	}
}
