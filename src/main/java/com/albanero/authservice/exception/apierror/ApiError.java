package com.albanero.authservice.exception.apierror;

import com.albanero.authservice.exception.LowerCaseClassNameResolver;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonTypeIdResolver;
import lombok.Data;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.List;

import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.ACTION_FAILED_EXCEPTION;


@Data
@JsonTypeInfo(include = JsonTypeInfo.As.EXISTING_PROPERTY, use = JsonTypeInfo.Id.CUSTOM, property = "error", visible = true)
@JsonTypeIdResolver(LowerCaseClassNameResolver.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiError {

    private HttpStatus status;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "dd-MM-yyyy hh:mm:ss")
    private LocalDateTime timestamp;

    private String message;

    private List<String> validationMessage;

    private Boolean success;

    private Object payload;

    private ApiError() {
        timestamp = LocalDateTime.now();
    }

    public ApiError(HttpStatus status) {
        this();
        this.status = status;
        this.message = String.valueOf(ACTION_FAILED_EXCEPTION);
    }

    public ApiError(HttpStatus status, String message) {
        this();
        this.status = status;
        this.message = message;
        this.success = false;
    }

    public ApiError(HttpStatus status, String message, List<String> validationMessage) {
        this();
        this.status = status;
        this.message = message;
        this.validationMessage = validationMessage;
        this.success = false;
    }
}
