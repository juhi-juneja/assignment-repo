package com.uxpsystems.assignment.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Component
public class UserAuthenticationEntryPoint extends BasicAuthenticationEntryPoint {

	//In case the authentication fails , this method must be invoked 
	@Override
	public void commence(HttpServletRequest request,
			HttpServletResponse response, AuthenticationException authException)
			throws IOException, ServletException {
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		System.out.println("Inside UserAuthenticationEntryPoint:commence");
		response.setContentType("application/json");
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.getOutputStream().println(
				"{ \"error\": \"" + authException.getMessage() + "\" }");
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		setRealmName("TEST REALM");
	}

}
