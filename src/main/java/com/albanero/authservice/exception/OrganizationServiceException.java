package com.albanero.authservice.exception;

import com.albanero.authservice.common.constants.OrganizationMessageConstants;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;


@Data
@EqualsAndHashCode(callSuper=false)
public class OrganizationServiceException extends RuntimeException{

    private final HttpStatus httpStatus;

    public OrganizationServiceException(OrganizationMessageConstants msg) {
        super(String.valueOf(msg));
        httpStatus = HttpStatus.BAD_REQUEST;
    }
    public OrganizationServiceException(String msg, HttpStatus httpStatus) {
        super(msg);
        this.httpStatus = httpStatus;
    }

    public OrganizationServiceException(String msg, HttpStatusCode httpStatusCode) {
        this(msg, HttpStatus.valueOf(httpStatusCode.value()));
    }
    public OrganizationServiceException(OrganizationMessageConstants msg, HttpStatusCode httpStatusCode) {
        this(msg, HttpStatus.valueOf(httpStatusCode.value()));
    }

    public OrganizationServiceException(OrganizationMessageConstants msg, HttpStatus httpStatus) {
        super(String.valueOf(msg));
        this.httpStatus = httpStatus;
    }

    public OrganizationServiceException(OrganizationMessageConstants msg, Throwable cause, HttpStatus httpStatus) {
        super(String.valueOf(msg), cause);
        this.httpStatus = httpStatus;
    }

    public OrganizationServiceException(Throwable cause, HttpStatus httpStatus) {
        super(cause);
        this.httpStatus = httpStatus;
    }

}
