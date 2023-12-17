package com.security.springsecdemo.resources;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

@RestController
public class DemoController {

	@GetMapping("/get")
	public String getData() {
		return "this is get call";
	}
	
	@GetMapping("/csrf")
	public CsrfToken getData(HttpServletRequest request) {
		return (CsrfToken) request.getAttribute("_csrf");
	}
	
	
	@PostMapping("/post")
	public String postData() {
		return "this is post call";
	}
	
	
}
