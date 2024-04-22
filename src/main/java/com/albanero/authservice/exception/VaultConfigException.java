package com.albanero.authservice.exception;

import org.springframework.http.HttpStatus;

public class VaultConfigException extends RuntimeException{
    private static final long serialVersionUID = 1L;

    private final HttpStatus httpStatus;

    public VaultConfigException(HttpStatus httpStatus) {
        super();
        this.httpStatus = httpStatus;
    }

    public VaultConfigException(String msg, HttpStatus httpStatus) {
        super(msg);
        this.httpStatus = httpStatus;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

}
