package com.uxpsystems.assignment.dto;

import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;

public class ApiErrorResponse {

	//http status code
    private HttpStatus status;

    // in case we want to provide API based custom error code
    private Integer error_code;

    // customer error message to the client API
    private String message;

    // Any furthur details which can help client API
    private String detail;

    // Time of the error.make sure to define a standard time zone to avoid any confusion.
    private LocalDateTime timeStamp;

	public ApiErrorResponse() {
		super();
		// TODO Auto-generated constructor stub
	}

	public ApiErrorResponse(HttpStatus status, String message) {
		super();
		this.status = status;
		this.message = message;
	}

	public ApiErrorResponse(HttpStatus status, Integer error_code,
			String message, String detail, LocalDateTime timeStamp) {
		super();
		this.status = status;
		this.error_code = error_code;
		this.message = message;
		this.detail = detail;
		this.timeStamp = timeStamp;
	}

	public HttpStatus getStatus() {
		return status;
	}

	public void setStatus(HttpStatus status) {
		this.status = status;
	}

	public Integer getError_code() {
		return error_code;
	}

	public void setError_code(Integer error_code) {
		this.error_code = error_code;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public String getDetail() {
		return detail;
	}

	public void setDetail(String detail) {
		this.detail = detail;
	}

	public LocalDateTime getTimeStamp() {
		return timeStamp;
	}

	public void setTimeStamp(LocalDateTime timeStamp) {
		this.timeStamp = timeStamp;
	}

	@Override
	public String toString() {
		return "ApiErrorResponse [status=" + status + ", message=" + message
				+ "]";
	}

}
