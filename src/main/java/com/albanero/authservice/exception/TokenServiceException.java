package com.albanero.authservice.exception;

import com.albanero.authservice.common.constants.ExceptionMessagesConstants;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

public class TokenServiceException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final HttpStatus httpStatus;


    public TokenServiceException(HttpStatus httpStatus) {
        super();
        this.httpStatus = httpStatus;
    }

    public TokenServiceException(HttpStatusCode httpStatusCode) {
        this(HttpStatus.valueOf(httpStatusCode.value()));
    }


    public TokenServiceException(String msg, HttpStatusCode httpStatusCode) {
        this(msg, HttpStatus.valueOf(httpStatusCode.value()));
    }

    public TokenServiceException(String msg, HttpStatus httpStatus) {
        super(msg);
        this.httpStatus = httpStatus;
    }

    public TokenServiceException(ExceptionMessagesConstants msg, HttpStatus httpStatus) {
        super(String.valueOf(msg));
        this.httpStatus = httpStatus;
    }

    public TokenServiceException(String msg, Throwable cause, HttpStatus httpStatus) {
        super(msg, cause);
        this.httpStatus = httpStatus;
    }

    public TokenServiceException(Throwable cause, HttpStatus httpStatus) {
        super(cause);
        this.httpStatus = httpStatus;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
