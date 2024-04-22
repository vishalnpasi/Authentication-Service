package com.albanero.authservice.exception;

import com.albanero.authservice.common.constants.ExceptionMessagesConstants;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class RBAServiceException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final HttpStatus httpStatus;

    public RBAServiceException(HttpStatus httpStatus) {
        super();
        this.httpStatus = httpStatus;
    }

    public RBAServiceException(String msg, HttpStatus httpStatus) {
        super(msg);
        this.httpStatus = httpStatus;
    }

    public RBAServiceException(ExceptionMessagesConstants msg, HttpStatus httpStatus) {
        super(String.valueOf(msg));
        this.httpStatus = httpStatus;
    }

    public RBAServiceException(String msg, Throwable cause, HttpStatus httpStatus) {
        super(msg, cause);
        this.httpStatus = httpStatus;
    }

    public RBAServiceException(Throwable cause, HttpStatus httpStatus) {
        super(cause);
        this.httpStatus = httpStatus;
    }

}
