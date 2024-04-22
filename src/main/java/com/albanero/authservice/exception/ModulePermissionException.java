package com.albanero.authservice.exception;

import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.http.HttpStatus;

@Data
@EqualsAndHashCode(callSuper = false)
public class ModulePermissionException extends RuntimeException{
    private static final long serialVersionUID = 1L;

    private final HttpStatus httpStatus;

    public ModulePermissionException(String msg) {
        super(msg);
        httpStatus = null;
    }

    public ModulePermissionException(String msg, HttpStatus status) {
        super(msg);
        httpStatus = status;
    }

    public ModulePermissionException(HttpStatus httpStatus) {
        super();
        this.httpStatus = httpStatus;
    }

    public ModulePermissionException(String msg, Throwable cause, HttpStatus httpStatus) {
        super(msg, cause);
        this.httpStatus = httpStatus;
    }

    public ModulePermissionException(Throwable cause, HttpStatus httpStatus) {
        super(cause);
        this.httpStatus = httpStatus;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
