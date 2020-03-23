package com.uxpsystems.assignment.dao;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.validation.constraints.NotBlank;

import com.uxpsystems.assignment.dto.AccountStatus;

@Entity
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private long id;
	@Column(unique = true)
	@NotBlank
	private String username;
	@NotBlank
	private String password;
	private AccountStatus status;
	private String roles;
	

	public User(@NotBlank String username, @NotBlank String password) {
		super();
		this.username = username;
		this.password = password;
	}
	

	public User(@NotBlank String username, @NotBlank String password,
			AccountStatus status) {
		super();
		this.username = username;
		this.password = password;
		this.status = status;
	}


	public User(@NotBlank String username, @NotBlank String password,
			AccountStatus status, String roles) {
		super();
		this.username = username;
		this.password = password;
		this.status = status;
		this.roles = roles;
	}


	public User() {
		super();
	}
	
	public String getRoles() {
		return roles;
	}


	public void setRoles(String roles) {
		this.roles = roles;
	}


	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public AccountStatus getStatus() {
		return status;
	}

	public void setStatus(AccountStatus status) {
		this.status = status;
	}


	@Override
	public String toString() {
		return "User [id=" + id + ", username=" + username + ", password="
				+ password + ", status=" + status + ", roles=" + roles + "]";
	}

}
