package com.uxpsystems.assignment.service;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.util.UriComponentsBuilder;

import com.uxpsystems.assignment.dao.User;

public interface UserService {

	ResponseEntity<Object> registerUser(User user,
			UriComponentsBuilder ucBuilder);

	ResponseEntity<Object> getUser(long userId);

	ResponseEntity<Object> updateUserRegistration(User user, long userId);

	ResponseEntity<List<User>> getAllUsers();

	ResponseEntity<Object> deleteUser(long userId);

}
