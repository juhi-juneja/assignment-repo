package com.uxpsystems.assignment.exception;

public class InternalServerErrorException extends CustomException{

	private static final long serialVersionUID = 1L;

	public InternalServerErrorException(String message) {
		super(message);
	}
}
