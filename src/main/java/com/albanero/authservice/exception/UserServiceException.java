package com.albanero.authservice.exception;

import com.albanero.authservice.common.constants.ExceptionMessagesConstants;
import org.springframework.http.HttpStatus;

public class UserServiceException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final HttpStatus httpStatus;


    public UserServiceException(HttpStatus httpStatus) {
        super();
        this.httpStatus = httpStatus;
    }

    public UserServiceException(String msg, HttpStatus httpStatus) {
        super(msg);
        this.httpStatus = httpStatus;
    }


    public UserServiceException(ExceptionMessagesConstants msg, HttpStatus httpStatus) {
        super(String.valueOf(msg));
        this.httpStatus = httpStatus;
    }

    public UserServiceException(String msg, Throwable cause, HttpStatus httpStatus) {
        super(msg, cause);
        this.httpStatus = httpStatus;
    }

    public UserServiceException(Throwable cause, HttpStatus httpStatus) {
        super(cause);
        this.httpStatus = httpStatus;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
