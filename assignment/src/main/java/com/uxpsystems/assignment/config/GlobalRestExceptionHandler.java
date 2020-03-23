package com.uxpsystems.assignment.config;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import com.uxpsystems.assignment.dto.ApiErrorResponse;
import com.uxpsystems.assignment.exception.BadRequestException;
import com.uxpsystems.assignment.exception.CustomException;
import com.uxpsystems.assignment.exception.InternalServerErrorException;
import com.uxpsystems.assignment.exception.NotFoundException;

@RestControllerAdvice
public class GlobalRestExceptionHandler extends ResponseEntityExceptionHandler {

	private Map<Class, HttpStatus> mapStatus = new HashMap<Class, HttpStatus>();

	public GlobalRestExceptionHandler() {
		super();
		mapStatus.put(BadRequestException.class, HttpStatus.BAD_REQUEST);
		mapStatus.put(NotFoundException.class, HttpStatus.NOT_FOUND);
		mapStatus.put(InternalServerErrorException.class,
				HttpStatus.INTERNAL_SERVER_ERROR);
	}

	//Handles all the Custom Runtime Exceptions
	@ExceptionHandler(CustomException.class)
	private ResponseEntity<ApiErrorResponse> handleClientException(
			CustomException ex) {
		ApiErrorResponse errorResponse = new ApiErrorResponse(mapStatus.get(ex
				.getClass()), mapStatus.get(ex.getClass()).value(),
				ex.getMessage(), ex.getStack(),
				LocalDateTime.now(ZoneOffset.UTC));
		return new ResponseEntity<ApiErrorResponse>(errorResponse,
				mapStatus.get(ex.getClass()));
	}

	//Handles all the Runtime(Internal server Exceptions) Exceptions
	@ExceptionHandler(RuntimeException.class)
	private ResponseEntity<ApiErrorResponse> handleServerException(
			CustomException ex) {
		ApiErrorResponse errorResponse = new ApiErrorResponse(mapStatus.get(ex
				.getClass()), mapStatus.get(ex.getClass()).value(),
				"Please Contact Administrator", ex.getStack(),
				LocalDateTime.now(ZoneOffset.UTC));

		return new ResponseEntity<ApiErrorResponse>(errorResponse,
				mapStatus.get(ex.getClass()));
	}

}
