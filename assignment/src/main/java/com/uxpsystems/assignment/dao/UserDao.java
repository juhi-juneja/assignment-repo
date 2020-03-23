package com.uxpsystems.assignment.dao;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.uxpsystems.assignment.dto.AccountStatus;

@Repository
public class UserDao {

	@Autowired
	UserRepository userRepository;

	public User saveUser(User user) {
		return userRepository.save(user);
	}

	public Optional<User> findUserByUsername(String username) {
		return userRepository.findByUsername(username);
	}

	public List<User> findAllUsers() {
		return userRepository.findAll();
	}

	public Optional<User> findUserById(long userId) {
		return userRepository.findById(userId);
	}

	public User updateUser(User existingUser) {
		return userRepository.save(existingUser);
	}

	public void deleteById(long userId) {
		userRepository.deactivateUserById(userId, AccountStatus.DEACTIVATED);
	}

	public Optional<List<User>> findAllActiveUsers(AccountStatus status) {
		return userRepository.findAllActiveUsers(status);
	}

	public Optional<User> findActiveUserById(long userId, AccountStatus status) {
		return userRepository.findActiveUserById(userId, status);
	}

}
