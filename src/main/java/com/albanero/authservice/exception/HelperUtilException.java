package com.albanero.authservice.exception;

import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.http.HttpStatus;

@Data
@EqualsAndHashCode(callSuper=false)
public class HelperUtilException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final HttpStatus httpStatus;

    public HelperUtilException(String msg) {
        super(msg);
        httpStatus = null;
    }

    public HelperUtilException(String msg, HttpStatus status) {
        super(msg);
        httpStatus = status;
    }

    public HelperUtilException(HttpStatus httpStatus) {
        super();
        this.httpStatus = httpStatus;
    }

    public HelperUtilException(String msg, Throwable cause, HttpStatus httpStatus) {
        super(msg, cause);
        this.httpStatus = httpStatus;
    }

    public HelperUtilException(Throwable cause, HttpStatus httpStatus) {
        super(cause);
        this.httpStatus = httpStatus;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
