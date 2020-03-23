package com.uxpsystems.assignment;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@SpringBootApplication
@EnableWebMvc
public class UxpsystemsAssignment {

	public static void main(String[] args) {
		System.out.println("Starting application with environment");
		SpringApplication.run(UxpsystemsAssignment.class, args);
		System.out.println("Application started successfully");
	}
}
