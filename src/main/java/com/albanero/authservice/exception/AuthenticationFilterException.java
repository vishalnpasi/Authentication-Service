package com.albanero.authservice.exception;

import org.springframework.http.HttpStatus;



public class AuthenticationFilterException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final HttpStatus httpStatus;

    public AuthenticationFilterException(String msg) {
        super(msg);
        httpStatus = null;
    }

    public AuthenticationFilterException(String msg, HttpStatus status) {
        super(msg);
        httpStatus = status;
    }

    public AuthenticationFilterException(HttpStatus httpStatus) {
        super();
        this.httpStatus = httpStatus;
    }

    public AuthenticationFilterException(String msg, Throwable cause, HttpStatus httpStatus) {
        super(msg, cause);
        this.httpStatus = httpStatus;
    }

    public AuthenticationFilterException(Throwable cause, HttpStatus httpStatus) {
        super(cause);
        this.httpStatus = httpStatus;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
