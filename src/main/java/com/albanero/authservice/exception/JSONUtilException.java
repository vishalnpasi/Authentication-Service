package com.albanero.authservice.exception;


import org.springframework.http.HttpStatus;

public class JSONUtilException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final HttpStatus httpStatus;

    public JSONUtilException(HttpStatus httpStatus) {
        super();
        this.httpStatus = httpStatus;
    }

    public JSONUtilException(String msg, HttpStatus httpStatus) {
        super(msg);
        this.httpStatus = httpStatus;
    }

    public JSONUtilException(String msg, Throwable cause, HttpStatus httpStatus) {
        super(msg, cause);
        this.httpStatus = httpStatus;
    }

    public JSONUtilException(Throwable cause, HttpStatus httpStatus) {
        super(cause);
        this.httpStatus = httpStatus;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
