package com.uxpsystems.assignment.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.uxpsystems.assignment.dao.User;
import com.uxpsystems.assignment.dao.UserRepository;
import com.uxpsystems.assignment.dto.UserDetailsModel;

@Service
@ComponentScan({"com.uxpsystems.assignment,com.uxpsystems.assignment.dao"})
public class UserDetailsServiceImpl implements UserDetailsService {

	@Autowired
	private UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
		
		System.out.println("Inside UserDetailsServiceImpl:loadUserByUsername() ");
		Optional<User> user = userRepository.findByUsername(username);
		System.out.println("User from repository:- "+user.get());
		user.orElseThrow(() ->new RuntimeException("User Not Found"));
		return user.map(UserDetailsModel::new).get();
	}

}
