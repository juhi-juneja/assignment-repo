package com.uxpsystems.assignment.controller;

import java.util.List;

import javax.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import com.uxpsystems.assignment.dao.User;
import com.uxpsystems.assignment.service.UserService;

@RestController
@RequestMapping(value="/assignment")
public class UserController {

	@Autowired
	UserService userService;
	
	@RequestMapping(value="/users",method=RequestMethod.POST , consumes = {"application/json"})
	public ResponseEntity<Object> registerUser(@Valid @RequestBody User user,UriComponentsBuilder ucBuilder){
		System.out.println("Inside UserController:registerUser");
		return userService.registerUser(user,ucBuilder);
	}
	
	@RequestMapping(value="/users/{userId}",method=RequestMethod.PUT, consumes = {"application/json"} )
	public ResponseEntity<Object> updateUserRegistration(@Valid @RequestBody User user,@PathVariable(name = "userId") Long userId){
		System.out.println("Inside UserController:updateUserRegistration");
		return userService.updateUserRegistration(user,userId);
	}
	
	@RequestMapping(value="/users/{userId}",method=RequestMethod.GET, produces = {"application/json"} )
	public ResponseEntity<Object> getUser(@PathVariable(name = "userId") Long userId){
		System.out.println("Inside UserController:getUser");
		return userService.getUser(userId);
	}
	
	@RequestMapping(value="/users",method=RequestMethod.GET, produces = {"application/json"} )
	public ResponseEntity<List<User>> getAllUsers(){
		System.out.println("Inside UserController:getAllUsers");
		return userService.getAllUsers();
	}
	
	@RequestMapping(value="/users/{userId}",method=RequestMethod.DELETE )
	public ResponseEntity<Object> deleteUser(@PathVariable(name = "userId") Long userId){
		System.out.println("Inside UserController:deleteUser");
		 return userService.deleteUser(userId);
	}
	
}
