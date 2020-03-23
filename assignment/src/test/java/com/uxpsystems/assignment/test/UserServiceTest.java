package com.uxpsystems.assignment.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.test.context.junit4.SpringRunner;

import com.uxpsystems.assignment.dao.User;
import com.uxpsystems.assignment.dao.UserDao;
import com.uxpsystems.assignment.dto.AccountStatus;
import com.uxpsystems.assignment.exception.BadRequestException;
import com.uxpsystems.assignment.exception.NotFoundException;
import com.uxpsystems.assignment.service.UserService;

@SpringBootTest
@RunWith(SpringRunner.class)
public class UserServiceTest {

	@Autowired
	UserService userService;

	@MockBean
	UserDao mockedUserDao;

	@Test
	public void testRegisterUser() {
		User user = new User("juhi", "password", AccountStatus.ACTIVATED);
		when(mockedUserDao.saveUser(user)).thenReturn(user);
		assertEquals(HttpStatus.CREATED, userService.registerUser(user, null)
				.getStatusCode());
		verify(mockedUserDao, times(1)).saveUser(user);
	}

	// Negative
	@Test(expected = BadRequestException.class)
	public void testDuplicateUserRegistration() {
		User user = new User("juhi", "password", AccountStatus.ACTIVATED);
		when(mockedUserDao.saveUser(user)).thenReturn(user);
		when(mockedUserDao.findUserByUsername(user.getUsername())).thenReturn(
				Optional.of(user));
		assertFalse(HttpStatus.CREATED.equals(userService.registerUser(user,
				null).getStatusCode()));
		verify(mockedUserDao, times(2)).saveUser(user);
	}

	@Test
	public void testGetUserById() {
		long userId = 1;
		Optional<User> user = Optional.of(new User("juhi", "password",
				AccountStatus.ACTIVATED));
		when(mockedUserDao.findActiveUserById(userId, AccountStatus.ACTIVATED))
				.thenReturn(user);
		assertEquals(user.get(), userService.getUser(userId).getBody());
	}
	
	@Test
	public void testGetAllUsers() {
		when(mockedUserDao.findAllActiveUsers(AccountStatus.ACTIVATED))
				.thenReturn(
						Optional.of(Stream.of(
								new User("Juhi", "password",
										AccountStatus.ACTIVATED),
								new User("Neha", "password123",
										AccountStatus.ACTIVATED)).collect(
								Collectors.toList())));
		assertEquals(2, userService.getAllUsers().getBody().size());
	}

	@Test(expected = NotFoundException.class)
	public void testUpdateUser() {
		long userId = 1;
		User user = new User("juhi", "password123", AccountStatus.ACTIVATED);
		when(mockedUserDao.updateUser(user)).thenReturn(user);
		assertEquals(HttpStatus.NOT_FOUND,
				userService.updateUserRegistration(user, userId)
						.getStatusCode());
		verify(mockedUserDao, times(1)).findActiveUserById(userId,
				AccountStatus.ACTIVATED);
		verify(mockedUserDao, times(0)).updateUser(user);
	}

	@Test(expected = NotFoundException.class)
	public void testDeleteUser() {
		long userId = 1;
		assertEquals(HttpStatus.NOT_FOUND, userService.deleteUser(userId)
				.getStatusCode());
		verify(mockedUserDao, times(1)).findActiveUserById(userId,
				AccountStatus.ACTIVATED);
		verify(mockedUserDao, times(0)).deleteById(userId);
	}

}
