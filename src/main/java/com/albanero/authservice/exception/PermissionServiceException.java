package com.albanero.authservice.exception;


import com.albanero.authservice.common.constants.ExceptionMessagesConstants;
import org.springframework.http.HttpStatus;

public class PermissionServiceException extends RuntimeException{
    private static final long serialVersionUID = 1L;
    private final HttpStatus httpStatus;
    
    public PermissionServiceException(String msg) {
        super(String.valueOf(msg));
        httpStatus = null;
    }
    public PermissionServiceException(ExceptionMessagesConstants msg) {
        super(String.valueOf(msg));
        httpStatus = null;
    }
    public PermissionServiceException(String msg, HttpStatus status) {
        super(msg);
        httpStatus = status;
    }

    public PermissionServiceException(HttpStatus httpStatus) {
        super();
        this.httpStatus = httpStatus;
    }

    public PermissionServiceException(String msg, Throwable cause, HttpStatus httpStatus) {
        super(msg, cause);
        this.httpStatus = httpStatus;
    }

    public PermissionServiceException(Throwable cause, HttpStatus httpStatus) {
        super(cause);
        this.httpStatus = httpStatus;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
