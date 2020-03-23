package com.uxpsystems.assignment.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import com.uxpsystems.assignment.dao.User;
import com.uxpsystems.assignment.dao.UserDao;
import com.uxpsystems.assignment.dao.UserRepository;
import com.uxpsystems.assignment.dto.AccountStatus;

//@DataJpaTest
@SpringBootTest
@RunWith(SpringRunner.class)
public class UserDaoTest {

	@Autowired
	UserDao userDao;

	@Autowired
	UserRepository userRepository;

	
	@Test
	public void testRegisterUser() throws Exception {
		User user = new User("Preeti", "password",AccountStatus.ACTIVATED);
		User savedUser = userDao.saveUser(user);
		long userId = savedUser.getId();
		System.out.println("User saved:- "+savedUser);
		assertEquals(user.getUsername(), userDao.findActiveUserById(userId, AccountStatus.ACTIVATED).get().getUsername());
	}
	
	//Negative 
	@Test
	public void testIfUserFetchedAfterDeletion() throws Exception{
		User user = new User("Preeti", "password",AccountStatus.ACTIVATED);
		User savedUser = userDao.saveUser(user);
		long userId = savedUser.getId();
		userDao.deleteById(userId);
		assertFalse(userDao.findActiveUserById(userId,AccountStatus.ACTIVATED).equals(Optional.of(savedUser)));
	}
	
	@Test
	public void testGetAllUsers() throws Exception {
		List<User> userList = Stream.of(new User("Juhi", "password",AccountStatus.ACTIVATED),
				new User("Neha", "password123",AccountStatus.ACTIVATED)).collect(Collectors.toList());
		userList.forEach((u) -> userDao.saveUser(u));
		assertEquals(2, userDao.findAllActiveUsers(AccountStatus.ACTIVATED).get().size());
	}
	
	@Test
	public void testGetUser() throws Exception {
		User user = new User("Preeti", "password",AccountStatus.ACTIVATED);
		User savedUser = userDao.saveUser(user);
		long userId = savedUser.getId();
		assertEquals(user.getUsername(), userDao.findActiveUserById(userId, AccountStatus.ACTIVATED).get()
				.getUsername());
	}

	@Test
	public void testUpdateUser() throws Exception {
		User user = new User("Preeti", "password",AccountStatus.ACTIVATED);
		userDao.saveUser(user);
		User newUser = new User("Preeti123", "password",AccountStatus.ACTIVATED);
		User savedUser = userDao.updateUser(newUser);
		assertEquals(newUser.getUsername(), savedUser.getUsername());
	}

	@Test
	public void testDeleteUser() throws Exception {
		User user = new User("Preeti", "password",AccountStatus.ACTIVATED);
		long userId = userDao.saveUser(user).getId();
		userDao.deleteById(userId);
		assertEquals(userDao.findActiveUserById(userId,AccountStatus.ACTIVATED), Optional.empty());
	}

	@After
	public void clearDb() {
		userRepository.deleteAll();
	}

}
