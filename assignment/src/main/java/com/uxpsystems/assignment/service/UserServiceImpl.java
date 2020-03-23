package com.uxpsystems.assignment.service;

import java.util.List;
import java.util.Optional;

import javax.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import com.uxpsystems.assignment.dao.User;
import com.uxpsystems.assignment.dao.UserDao;
import com.uxpsystems.assignment.dao.UserRepository;
import com.uxpsystems.assignment.dto.AccountStatus;
import com.uxpsystems.assignment.exception.BadRequestException;
import com.uxpsystems.assignment.exception.InternalServerErrorException;
import com.uxpsystems.assignment.exception.NotFoundException;

@Service
@Transactional
public class UserServiceImpl implements UserService {

	@Autowired
	UserRepository userRepository;

	@Autowired
	UserDao userDao;
	
	@Autowired
	PasswordEncoder passwordEncoder;

	private final String RESOURCE_URL = "/assignment/users/";

	@Override
	public ResponseEntity<Object> registerUser(User user,
			UriComponentsBuilder ucBuilder) {

		System.out.println("Inside UserServiceImpl:registerUser");
		if (isUserExist(user)) {
			System.out.println("A User with name " + user.getUsername()
					+ " already exist");
			throw new BadRequestException("User already exist");
		}
		// Activate user's account on registration
		user.setStatus(AccountStatus.ACTIVATED);
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		try {
			userDao.saveUser(user);
		} catch (Exception e) {
			throw new InternalServerErrorException("Unable to process request for registering user");
		}
		HttpHeaders headers = new HttpHeaders();
		//Provide the link to access the newly registered user
		if (ucBuilder != null)
			headers.setLocation(ucBuilder.path(RESOURCE_URL + "{id}")
					.buildAndExpand(user.getId()).toUri());
		return new ResponseEntity<Object>(new String(
				"User is successfully created with username "
						+ user.getUsername()), headers, HttpStatus.CREATED);

	}

	private boolean isUserExist(User user) {
		Optional<User> existingUser = userDao.findUserByUsername(user
				.getUsername());
		return existingUser.isPresent() ? true : false;
	}

	//Returns list of active users 
	@Override
	public ResponseEntity<List<User>> getAllUsers() {
		System.out.println("Inside UserServiceImpl:getAllUsers");
		Optional<List<User>> users = userDao
				.findAllActiveUsers(AccountStatus.ACTIVATED);
		if (!users.isPresent()) {
			throw new NotFoundException("User does not exist");
		}
		return new ResponseEntity<List<User>>(users.get(), HttpStatus.OK);
	}

	//Returns user if the user's account is activated
	@Override
	public ResponseEntity<Object> getUser(long userId) {
		System.out.println("Inside UserServiceImpl:getUser");
		Optional<User> existingUser = userDao.findActiveUserById(userId,
				AccountStatus.ACTIVATED);
		if (!existingUser.isPresent()) {
			throw new NotFoundException("User does not exist");
		}
		return new ResponseEntity<Object>(existingUser.get(), HttpStatus.OK);
	}

	//Updates the user by username , password or status
	@Override
	public ResponseEntity<Object> updateUserRegistration(User user, long userId) {
		System.out.println("Inside UserServiceImpl:updateUserRegistration");
		System.out.println("New User:- "+user);
		Optional<User> existingUserOp = userDao.findUserById(userId);
		if (!existingUserOp.isPresent()) {
			throw new NotFoundException("User does not exist");
		}
		User existingUser = existingUserOp.get();
		existingUser.setPassword(passwordEncoder.encode(user.getPassword()));
		if(!(user.getStatus().equals(AccountStatus.ACTIVATED)|| user.getStatus().equals(AccountStatus.DEACTIVATED)))
			throw new BadRequestException("Please provide appropriate value for status");
		else {
			if(user.getStatus().name() == "ACTIVATED") 
				existingUser.setStatus(AccountStatus.ACTIVATED);
			else
				existingUser.setStatus(AccountStatus.DEACTIVATED);
		}
		existingUser.setUsername(user.getUsername());
		existingUser.setRoles(user.getRoles());
		try {
			userDao.updateUser(existingUser);
		} catch (Exception e) {
			throw new InternalServerErrorException("Unable to process request");
		}
		return new ResponseEntity<Object>(new String(
				"User is successfully updated with username "
						+ user.getUsername()), HttpStatus.OK);
	}

	//Soft deletes the user, deactivating the account
	@Override
	//@Secured("ROLE_ADMIN")
	public ResponseEntity<Object> deleteUser(long userId) {
		System.out.println("Inside UserServiceImpl:deleteUser");
		Optional<User> existingUserOp = userDao.findUserById(userId);
		if (!existingUserOp.isPresent()) {
			throw new NotFoundException("User does not exist");
		}
		try {
			userDao.deleteById(userId);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalServerErrorException("Unable to process request");
		}
		return new ResponseEntity<Object>(new String("User is successfully deleted"),HttpStatus.NO_CONTENT);
	}

}
