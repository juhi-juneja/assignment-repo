package com.uxpsystems.assignment.test;

import static org.mockito.Mockito.when;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.*;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.web.config.EnableSpringDataWebSupport;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.uxpsystems.assignment.config.UserAuthenticationEntryPoint;
import com.uxpsystems.assignment.dao.User;
import com.uxpsystems.assignment.dao.UserRepository;
import com.uxpsystems.assignment.service.UserDetailsServiceImpl;
import com.uxpsystems.assignment.service.UserService;

@RunWith(SpringRunner.class)
@WebMvcTest
@ComponentScan(basePackages = {"com.uxpsystems.assignment.service","com.uxpsystems.assignment.dao", 
		"com.uxpsystems.assignment.config"
})
public class UserControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private UserService mockedUserService;

	@Autowired
	private ObjectMapper mapper;

	@Test
	public void testAccessProtectedWithoutCreds() throws Exception {
		mockMvc.perform(get("/assignment"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void testAccessProtectedWithWrongCreds() throws Exception {
		mockMvc.perform(
				get("/assignment").header("Authorization",
						"Basic anVoaTpwYXNzd29yZA")).andExpect(
				status().isNotFound());
	}

	@Test
	public void testGetAllUsers() throws Exception {
		List<User> userList = Stream.of(new User("Juhi", "password"),
				new User("Neha", "password123")).collect(Collectors.toList());
		ResponseEntity<List<User>> userList1 = new ResponseEntity<List<User>>(
				userList, HttpStatus.OK);
		when(mockedUserService.getAllUsers()).thenReturn(userList1);
		mockMvc.perform(
				get("/assignment/users")
						.contentType(MediaType.APPLICATION_JSON).header(
								"Authorization", "Basic anVoaTpwYXNzd29yZA=="))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$", hasSize(2)))
				.andExpect(jsonPath("$[0].username", is("Juhi")))
				.andExpect(jsonPath("$[0].password", is("password")))
				.andExpect(jsonPath("$[1].username", is("Neha")))
				.andExpect(jsonPath("$[1].password", is("password123")));

		verify(mockedUserService, times(1)).getAllUsers();
	}

	@Test
	public void testGetUsers() throws Exception {
		long userId = 1;
		ResponseEntity<Object> user = new ResponseEntity<Object>(new User(
				"Juhi", "password"), HttpStatus.OK);
		when(mockedUserService.getUser(userId)).thenReturn(user);
		mockMvc.perform(
				get("/assignment/users/{userId}", "1").contentType(
						MediaType.APPLICATION_JSON).header("Authorization",
						"Basic anVoaTpwYXNzd29yZA=="))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.username", is("Juhi")))
				.andExpect(jsonPath("$.password", is("password")));

		verify(mockedUserService, times(1)).getUser(userId);
	}

	@Test
	public void testRegisterUser() throws Exception {
		User user = new User("Juhi", "password");
		when(mockedUserService.registerUser(user, null)).thenReturn(
				new ResponseEntity<Object>(new String(
						"User is successfully created with username "
								+ user.getUsername()), HttpStatus.CREATED));
		mockMvc.perform(
				post("/assignment/users")
						.content(mapper.writeValueAsString(user))
						.contentType(MediaType.APPLICATION_JSON)
						.header("Authorization", "Basic anVoaTpwYXNzd29yZA=="))
				.andExpect(status().isOk());
	}

	@Test
	public void testUpdateUser() throws Exception {
		long userId = 1;
		User user = new User("Juhi", "password123");
		when(mockedUserService.updateUserRegistration(user, userId))
				.thenReturn(new ResponseEntity<Object>(HttpStatus.OK));
		mockMvc.perform(
				put("/assignment/users/{userId}", "1")
						.content(mapper.writeValueAsString(user))
						.contentType(MediaType.APPLICATION_JSON)
						.header("Authorization", "Basic anVoaTpwYXNzd29yZA=="))
				.andExpect(status().isOk());
	}

	@Test
	public void testDeleteUser() throws Exception {
		long userId = 1;
		when(mockedUserService.deleteUser(userId)).thenReturn(
				new ResponseEntity<Object>(HttpStatus.NO_CONTENT));
		mockMvc.perform(
				delete("/assignment/users/{userId}", "1").contentType(
						MediaType.APPLICATION_JSON).header("Authorization",
						"Basic anVoaTpwYXNzd29yZA==")).andExpect(
				status().isNoContent());
	}

}
