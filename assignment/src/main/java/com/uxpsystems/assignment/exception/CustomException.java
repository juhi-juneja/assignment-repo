package com.uxpsystems.assignment.exception;

public class CustomException extends RuntimeException {
	
	private static final long serialVersionUID = 1L;
	private String stack;

	public String getStack() {
		return stack;
	}

	public void setStack(String stack) {
		this.stack = stack;
	}
	public CustomException() {
		super();
	}

	public CustomException(String stack) {
		super();
		this.stack = stack;
	}
	

}
