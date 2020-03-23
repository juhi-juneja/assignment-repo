package com.uxpsystems.assignment.dto;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.uxpsystems.assignment.dao.User;

public class UserDetailsModel implements UserDetails {
	
	private static final long serialVersionUID = 1L;
	private String username;
	private String password;
	private AccountStatus status;
	private List<GrantedAuthority> authorities;
	
	public UserDetailsModel(){	}
	
	public UserDetailsModel(User user){
		this.username = user.getUsername();
		this.password = user.getPassword();
		this.status = user.getStatus();
		this.authorities = Arrays.stream(user.getRoles().split(","))
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
	}

	@Override
	public String getPassword() {
		// TODO Auto-generated method stub
		return password;
	}

	@Override
	public String getUsername() {
		// TODO Auto-generated method stub
		return username;
	}

	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return status==AccountStatus.ACTIVATED?true:false;
	}
	
	@Override
	public boolean isAccountNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		// TODO Auto-generated method stub
		return null;
	}
	
}
