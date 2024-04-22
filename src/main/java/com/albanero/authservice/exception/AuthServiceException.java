package com.albanero.authservice.exception;

import com.albanero.authservice.common.constants.ExceptionMessagesConstants;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.http.HttpStatus;

import java.io.Serial;

@Data
@EqualsAndHashCode(callSuper=false)
public class AuthServiceException extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 1L;

    private final HttpStatus httpStatus;

    private final transient Object payload;

    public AuthServiceException(HttpStatus httpStatus) {
        super();
        this.payload = null;
        this.httpStatus = httpStatus;
    }

    public AuthServiceException(String msg, HttpStatus httpStatus) {
        super(msg);
        this.payload = null;
        this.httpStatus = httpStatus;
    }

    public AuthServiceException(ExceptionMessagesConstants msg, HttpStatus httpStatus) {
        super(String.valueOf(msg));
        this.payload = null;
        this.httpStatus = httpStatus;
    }

    public AuthServiceException(ExceptionMessagesConstants msg, Object payload, HttpStatus httpStatus) {
        super(String.valueOf(msg));
        this.payload = payload;
        this.httpStatus = httpStatus;
    }

    public AuthServiceException(String msg, Throwable cause, HttpStatus httpStatus) {
        super(msg, cause);
        this.payload = null;
        this.httpStatus = httpStatus;
    }

    public AuthServiceException(Throwable cause, HttpStatus httpStatus) {
        super(cause);
        this.payload = null;
        this.httpStatus = httpStatus;
    }
}
