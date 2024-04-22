package com.albanero.authservice.exception.controller;

import com.albanero.authservice.exception.*;
import com.albanero.authservice.exception.apierror.ApiError;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.ArrayList;
import java.util.List;

import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.ACTION_FAILED_EXCEPTION;
import static org.springframework.http.HttpStatus.*;

@ControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
@Slf4j
public class RestExceptionHandlerController extends ResponseEntityExceptionHandler {

    private static final Logger REST_EXCEPTION_LOGGER = LoggerFactory.getLogger(RestExceptionHandlerController.class);

    /**
     * Handles AuthServiceException. Created to encapsulate errors with more detail than jakarta.persistence.AuthServiceException.
     *
     * @param ex {@link AuthServiceException}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(AuthServiceException.class)
    protected ResponseEntity<Object> handleAuthServiceException(AuthServiceException ex) {
        REST_EXCEPTION_LOGGER.error("Exception occurred in RestExceptionHandlerController::handleAuthService {}", ex.getMessage(), ex);
        ApiError apiError;
        if (ex.getHttpStatus() != null) apiError = new ApiError(ex.getHttpStatus());
        else apiError = new ApiError(BAD_REQUEST);
        if (ex.getPayload() != null) apiError.setPayload(ex.getPayload());
        apiError.setMessage(ex.getMessage());
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }

    /**
     * Handles AuthenticationFilterException. Created to encapsulate errors with more detail than jakarta.persistence.AuthenticationFilterException.
     *
     * @param ex {@link AuthenticationFilterException}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(AuthenticationFilterException.class)
    protected ResponseEntity<Object> handleAuthenticationFilterException(AuthenticationFilterException ex) {
        REST_EXCEPTION_LOGGER.error("Exception occurred in RestExceptionHandlerController::handleAuthenticationFilterException {}", ex.getMessage(), ex);
        ApiError apiError;
        if (ex.getHttpStatus() != null) apiError = new ApiError(ex.getHttpStatus());
        else apiError = new ApiError(INTERNAL_SERVER_ERROR);
        apiError.setMessage(ex.getMessage());
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }

    /**
     * Handles HelperUtilException. Created to encapsulate errors with more detail than jakarta.persistence.HelperUtilException.
     *
     * @param ex {@link HelperUtilException}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(HelperUtilException.class)
    protected ResponseEntity<Object> handleHelperUtilException(HelperUtilException ex) {
        REST_EXCEPTION_LOGGER.error("Exception occurred in RestExceptionHandlerController::handleHelperUtilException {}", ex.getMessage(), ex);
        ApiError apiError;
        if (ex.getHttpStatus() != null) apiError = new ApiError(ex.getHttpStatus());
        else apiError = new ApiError(BAD_REQUEST);
        apiError.setMessage(ex.getMessage());
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }
    /**
     * Handles ModulePermissionException. Created to encapsulate errors with more detail than jakarta.persistence.ModulePermissionException.
     *
     * @param ex {@link ModulePermissionException}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(ModulePermissionException.class)
    protected ResponseEntity<Object> handleModulePermissionException(ModulePermissionException ex) {
        REST_EXCEPTION_LOGGER.error("Exception occurred in RestExceptionHandlerController::handleModulePermissionException {}", ex.getMessage(), ex);
        ApiError apiError;
        if (ex.getHttpStatus() != null) apiError = new ApiError(ex.getHttpStatus());
        else apiError = new ApiError(BAD_REQUEST);
        apiError.setMessage(ex.getMessage());
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }

    /**
     * Handles ProjectServiceException. Created to encapsulate errors with more detail than jakarta.persistence.ProjectServiceException.
     *
     * @param ex {@link ProjectServiceException}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(ProjectServiceException.class)
    protected ResponseEntity<Object> handleProjectServiceException(ProjectServiceException ex) {
        REST_EXCEPTION_LOGGER.error("Exception occurred in RestExceptionHandlerController::handleProjectServiceException {}", ex.getMessage(), ex);
        ApiError apiError;
        if (ex.getHttpStatus() != null) apiError = new ApiError(ex.getHttpStatus());
        else apiError = new ApiError(BAD_REQUEST);
        apiError.setMessage(ex.getMessage());
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }

    /**
     * Handles UserRoleServiceException. Created to encapsulate errors with more detail than jakarta.persistence.UserRoleServiceException.
     *
     * @param ex {@link UserRoleServiceException}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(UserRoleServiceException.class)
    protected ResponseEntity<Object> handleUserRoleServiceException(UserRoleServiceException ex) {
        REST_EXCEPTION_LOGGER.error("Exception occurred in RestExceptionHandlerController::handleUserRoleServiceException {}", ex.getMessage(), ex);

        ApiError apiError;
        if (ex.getHttpStatus() != null) apiError = new ApiError(ex.getHttpStatus());
        else apiError = new ApiError(BAD_REQUEST);
        apiError.setMessage(ex.getMessage());
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }

    /**
     * Handles UserServiceException. Created to encapsulate errors with more detail than jakarta.persistence.UserServiceException.
     *
     * @param ex {@link UserServiceException}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(UserServiceException.class)
    protected ResponseEntity<Object> handleUserServiceException(UserServiceException ex) {
        REST_EXCEPTION_LOGGER.error("Exception occurred in RestExceptionHandlerController::handleUserServiceException {}", ex.getMessage(), ex);
        ApiError apiError;
        if (ex.getHttpStatus() != null) apiError = new ApiError(ex.getHttpStatus());
        else apiError = new ApiError(BAD_REQUEST);
        apiError.setMessage(ex.getMessage());
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }

    /**
     * Handles PermissionServiceException. Created to encapsulate errors with more detail than jakarta.persistence.PermissionServiceException.
     *
     * @param ex {@link PermissionServiceException}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(PermissionServiceException.class)
    protected ResponseEntity<Object> handlePermissionServiceException(PermissionServiceException ex) {
        REST_EXCEPTION_LOGGER.error("Exception occurred in RestExceptionHandlerController::handlePermissionServiceException {}", ex.getMessage(), ex);

        ApiError apiError;
        if (ex.getHttpStatus() != null) apiError = new ApiError(ex.getHttpStatus());
        else apiError = new ApiError(BAD_REQUEST);
        apiError.setMessage(ex.getMessage());
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }

    /**
     * Handles OrganizationServiceException. Created to encapsulate errors with more detail than OrganizationServiceException.
     *
     * @param ex {@link OrganizationServiceException}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(OrganizationServiceException.class)
    protected ResponseEntity<Object> handleOrganizationServiceException(OrganizationServiceException ex) {
        REST_EXCEPTION_LOGGER.error("Exception occurred in RestExceptionHandlerController::handleOrganizationServiceException {}", ex.getMessage(), ex);
        ApiError apiError;
        if (ex.getHttpStatus() != null) apiError = new ApiError(ex.getHttpStatus());
        else apiError = new ApiError(BAD_REQUEST);
        apiError.setMessage(ex.getMessage());
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }

    /**
     * Handles RequestUtilException. Created to encapsulate errors with more detail than jakarta.persistence.RequestUtilException.
     *
     * @param ex {@link RequestUtilException}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(RequestUtilException.class)
    protected ResponseEntity<Object> handleRequestUtilException(RequestUtilException ex) {
        REST_EXCEPTION_LOGGER.error("Exception occurred in RestExceptionHandlerController::handleRequestUtilException {}", ex.getMessage(), ex);
        ApiError apiError;
        if (ex.getHttpStatus() != null) apiError = new ApiError(ex.getHttpStatus());
        else apiError = new ApiError(BAD_REQUEST);
        apiError.setMessage(ex.getMessage());
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }

    /**
     * Handles RBAServiceException. Created to encapsulate errors with more detail than RBAServiceException.
     *
     * @param ex {@link RBAServiceException}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(RBAServiceException.class)
    protected ResponseEntity<Object> handleRBAServiceException(RBAServiceException ex) {
        REST_EXCEPTION_LOGGER.error("Exception occurred in RestExceptionHandlerController::handleRBAServiceException {}", ex.getMessage(), ex);
        ApiError apiError;
        if (ex.getHttpStatus() != null) apiError = new ApiError(ex.getHttpStatus());
        else apiError = new ApiError(INTERNAL_SERVER_ERROR);
        apiError.setMessage(ex.getMessage());
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }

    /**
     * Handles TokenServiceException. Created to encapsulate errors with more detail than jakarta.persistence.TokenServiceException.
     *
     * @param ex {@link TokenServiceException}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(TokenServiceException.class)
    protected ResponseEntity<Object> handleTokenServiceException(TokenServiceException ex) {
        REST_EXCEPTION_LOGGER.error("Exception occurred in RestExceptionHandlerController::handleTokenServiceException {}", ex.getMessage(), ex);

        ApiError apiError;
        if (ex.getHttpStatus() != null) apiError = new ApiError(ex.getHttpStatus());
        else apiError = new ApiError(INTERNAL_SERVER_ERROR);
        apiError.setMessage(ex.getMessage());
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }

    /**
     * Handles EmailUtilException. Created to encapsulate errors with more detail than jakarta.persistence.EmailUtilException.
     *
     * @param ex {@link EmailUtilException}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(EmailUtilException.class)
    protected ResponseEntity<Object> handleEmailUtilException(EmailUtilException ex) {
        REST_EXCEPTION_LOGGER.error("Exception occurred in RestExceptionHandlerController::handleEmailUtilException {}", ex.getMessage(), ex);
        ApiError apiError;
        if (ex.getHttpStatus() != null) apiError = new ApiError(ex.getHttpStatus());
        else apiError = new ApiError(INTERNAL_SERVER_ERROR);
        apiError.setMessage(ex.getMessage());
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }

    /**
     * Handles VaultConfigException. Created to encapsulate errors with more detail than jakarta.persistence.VaultConfigException.
     *
     * @param ex {@link VaultConfigException}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(VaultConfigException.class)
    protected ResponseEntity<Object> handleVaultConfigException(VaultConfigException ex) {
        REST_EXCEPTION_LOGGER.error("Exception occurred in RestExceptionHandlerController::handleVaultConfigException {}", ex.getMessage(), ex);
        ApiError apiError;
        if (ex.getHttpStatus() != null) apiError = new ApiError(ex.getHttpStatus());
        else apiError = new ApiError(INTERNAL_SERVER_ERROR);
        apiError.setMessage(ex.getMessage());
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }

    /**
     * Handles Throwable. Created to encapsulate errors with more detail than jakarta.persistence.Throwable.
     *
     * @param th {@link Throwable}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(Throwable.class)
    protected ResponseEntity<Object> handleThrowable(Throwable th) {
        REST_EXCEPTION_LOGGER.error("Exception occurred in RestExceptionHandlerController::handleThrowable {}", th.getMessage(), th);
        ApiError apiError;
        if (th.getMessage().contains("DataAccessResourceFailureException")) {
            apiError = new ApiError(SERVICE_UNAVAILABLE);
            apiError.setMessage("Database is Temporary unavailable, please try after some time.");
        } else {
            apiError = new ApiError(INTERNAL_SERVER_ERROR);
            apiError.setMessage(ACTION_FAILED_EXCEPTION.label);
        }
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }

    /**
     * Handles JSONUtilException. Created to encapsulate errors with more detail than jakarta.persistence.JSONUtilException.
     *
     * @param ex {@link HelperUtilException}
     * @return {@link ResponseEntity<Object>}
     */
    @ExceptionHandler(JSONUtilException.class)
    protected ResponseEntity<Object> handleJSONUtilException(JSONUtilException ex) {
        ApiError apiError;
        if (ex.getHttpStatus() != null) apiError = new ApiError(ex.getHttpStatus());
        else apiError = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR);
        apiError.setMessage(ex.getMessage());
        apiError.setSuccess(false);
        return buildResponseEntity(apiError);
    }

//    @Override
    @ResponseStatus(BAD_REQUEST)
    @ResponseBody
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
        BindingResult result = ex.getBindingResult();
        List<FieldError> fieldErrors = result.getFieldErrors();
        return processFieldErrors(fieldErrors);
    }

    private ResponseEntity<Object> processFieldErrors(List<org.springframework.validation.FieldError> fieldErrors) {
        List<String> validationError = new ArrayList<>();
        for (org.springframework.validation.FieldError fieldError : fieldErrors) {
            validationError.add(fieldError.getField() + " " + fieldError.getDefaultMessage());
        }
        ApiError apiError = new ApiError(BAD_REQUEST, "Validation Error", validationError);
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

    /**
     * Builds ResponseEntity Object.
     *
     * @param apiError {@link ApiError}
     * @return {@link ResponseEntity<Object>}
     */
    private ResponseEntity<Object> buildResponseEntity(ApiError apiError) {
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }
}
