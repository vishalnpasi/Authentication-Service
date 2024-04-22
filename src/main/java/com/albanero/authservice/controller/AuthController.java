package com.albanero.authservice.controller;

import com.albanero.authservice.common.constants.HttpHeaderConstants;
import com.albanero.authservice.common.constants.MappingConstants;
import com.albanero.authservice.common.constants.AuthConstants;
import com.albanero.authservice.common.constants.PathVariables;
import com.albanero.authservice.common.constants.RequestParams;
import com.albanero.authservice.common.dto.request.AuthRequest;
import com.albanero.authservice.common.dto.request.PasswordCheckRequest;
import com.albanero.authservice.common.dto.request.SecurityQuesRequest;
import com.albanero.authservice.common.dto.response.*;
import com.albanero.authservice.common.util.HelperUtil;
import com.albanero.authservice.common.util.RequestUtil;
import com.albanero.authservice.common.util.RestUtil;
import com.albanero.authservice.model.UserProfile;
import com.albanero.authservice.service.RBAService;
import com.albanero.authservice.service.TokenService;
import com.albanero.authservice.service.impl.AuthServiceImpl;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

import static com.albanero.authservice.common.constants.LoggerConstants.*;

/**
 * Class that provide Authentication end points mappings.
 *
 * @author arunima.mishra
 */
@RestController
@RequestMapping(MappingConstants.API_BASE)
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

    private static final String AUTH_CONTROLLER_CLASS = "AuthController";

    private final AuthServiceImpl authService;

    private final RequestUtil requestUtil;

    private final RBAService rbaService;

    private final TokenService tokenService;


    @Autowired
    public AuthController(AuthServiceImpl authService, RequestUtil requestUtil, RBAService rbaService, TokenService tokenService) {
        this.authService = authService;
        this.requestUtil = requestUtil;
        this.rbaService = rbaService;
        this.tokenService = tokenService;
    }

    /**
     * REST API responsible to login user and generate token
     *
     * @param authenticationRequest {@link AuthRequest}
     * @return {@link AuthResponse}
     */
    @PostMapping(path = AuthConstants.AUTHENTICATE)
    @Operation(summary = "AUTHENTICATE", description = "REST API responsible to login user and generate token")
    public ResponseEntity<BaseResponse> authenticate(
            HttpServletRequest request,
            @RequestBody AuthRequest authenticationRequest
    ) {
        String method = "authenticate";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        try {
            baseResponse = authService.authenticate(request, authenticationRequest);
            LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
            return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
        } catch (DisabledException e) {
            LOGGER.error(
                    AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, AUTH_CONTROLLER_CLASS, method,
                    e.getMessage(), e.getStackTrace());
            baseResponse.setMessage("User disabled exception Occurred while validating authentication token!");
            baseResponse.setSuccess(false);
            return new ResponseEntity<>(baseResponse, HttpStatus.UNAUTHORIZED);
        } catch (BadCredentialsException e) {
            LOGGER.error(
                    AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, AUTH_CONTROLLER_CLASS, method,
                    e.getMessage(), e.getStackTrace());
            UserProfile userProfile = authService.loadUserProfileByUsername(authenticationRequest.getUsername());
            if (userProfile != null) {
                FetchResponse requestDetails = rbaService.fetchRequestDetails(request);
                baseResponse = authService.incrementFailedAttempts(userProfile.getId(), requestDetails);
                if (Boolean.FALSE.equals(baseResponse.getSuccess())) {
                    baseResponse.setMessage("User can't Login because this IP is blocked due mutiple failed attempts to login!");
                    baseResponse.setSuccess(false);
                    return new ResponseEntity<>(baseResponse, HttpStatus.UNAUTHORIZED);
                }
            }
            baseResponse.setMessage("Either Password or Username is wrong!");
            baseResponse.setSuccess(false);
            return new ResponseEntity<>(baseResponse, HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * REST API responsible to login user and generate token
     *
     * @param authenticationRequest {@link AuthRequest}
     * @return {@link AuthResponse}
     */
    @PostMapping(path = AuthConstants.AUTHENTICATE_MFA)
    @Operation(summary = "AUTHENTICATE", description = "REST API responsible to login user with compulsory MFA")
    public ResponseEntity<BaseResponse> createAuthenticationToken(
            HttpServletRequest request,
            @RequestBody AuthRequest authenticationRequest
    ) {
        String method = "createAuthenticationToken";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        try {
            baseResponse = authService.authenticateMFA(request, authenticationRequest);
            LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
            return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
        } catch (DisabledException e) {
            LOGGER.error(
                    AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, AUTH_CONTROLLER_CLASS, method,
                    e.getMessage(), e.getStackTrace());
            baseResponse.setMessage("User disabled exception Occurred while validating authentication token!");
            baseResponse.setSuccess(false);
            return new ResponseEntity<>(baseResponse, HttpStatus.UNAUTHORIZED);
        } catch (BadCredentialsException e) {
            LOGGER.error(
                    AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, AUTH_CONTROLLER_CLASS, method,
                    e.getMessage(), e.getStackTrace());
            baseResponse.setMessage("Bad Credentials exception Occurred while validating authentication token!");
            baseResponse.setSuccess(false);
            return new ResponseEntity<>(baseResponse, HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * REST API responsible to verify the OTP for MFA
     *
     * @param verifyCodeRequest {@link AuthRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(AuthConstants.VERIFY_MFA)
    @Operation(summary = "VERIFY MFA", description = "REST API responsible to verify the OTP for MFA")
    public ResponseEntity<BaseResponse> verifyCode(@Validated @RequestBody AuthRequest verifyCodeRequest) {
        String method = "verifyCode";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse authResponse = authService.verify(verifyCodeRequest);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(authResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to validate token
     *
     * @param token {@link String}
     * @return {@link BaseResponse}
     */
    @GetMapping(AuthConstants.VALIDATE_TOKEN)
    @Operation(summary = "VALIDATE TOKEN", description = "REST API responsible to validate token")
    public ResponseEntity<BaseResponse> isTokenValid(
            @Parameter(description = "Token value which is to be validated", required = true) @PathVariable(RequestParams.TOKEN) String token
    ) {
        String method = "isTokenValid";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        Boolean tokenValidationResponse = tokenService.validateTokenRestTemplate(token);
        if (Boolean.TRUE.equals(tokenValidationResponse)) {
            baseResponse.setMessage("Token is valid.");
            baseResponse.setSuccess(true);
            return ResponseEntity.ok(baseResponse);
        }
        baseResponse.setMessage("Token is invalid.");
        baseResponse.setSuccess(false);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);
    }

    /**
     * REST API responsible to validate refresh token
     *
     * @param refreshToken {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(AuthConstants.VALIDATE_REFRESH_TOKEN)
    @Operation(summary = "VALIDATE REFRESH TOKEN", description = "REST API responsible to validate refresh token")
    public ResponseEntity<BaseResponse> isRefreshTokenValid(
            @Parameter(description = "Refresh Token value which is to be validated", required = true) @PathVariable(RequestParams.REFRESH_TOKEN) String refreshToken
    ) {
        String method = "isRefreshTokenValid";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = authService.validateRefreshToken(refreshToken);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);

    }

    /**
     * REST API responsible to invalidate refresh token
     *
     * @param username {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(AuthConstants.INVALIDATE_REFRESH_TOKEN)
    @Operation(summary = "INVALIDATE REFRESH TOKEN", description = "REST API responsible to invalidate refresh token")
    public ResponseEntity<BaseResponse> invalidateToken(
            @Parameter(description = "Username value to invalidate corresponding refresh token ", required = true) @PathVariable(RequestParams.USERNAME) String username
    ) {
        String method = "invalidateToken";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        authService.invalidateExistingRefreshToken(username);
        baseResponse.setMessage("Token has been invalidated.");
        baseResponse.setSuccess(true);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);
    }

    /**
     * REST API responsible to generate access and refresh tokens
     *
     * @param username {@link String}
     * @return {@link ResponseEntity<AuthResponse>}
     */
    @GetMapping(AuthConstants.GENERATE_TOKEN + PathVariables.USERNAME_PARAM)
    @Operation(summary = "GENERATE TOKEN", description = "REST API responsible to generate access and refresh tokens")
    public ResponseEntity<AuthResponse> generateToken(
            @Parameter(description = "Username value to generate access and refresh token for corresponding user", required = true) @PathVariable("username") String username
    ) {
        String method = "generateToken";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        AuthResponse baseResponse = authService.generateToken(username);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to check if MFA is enabled for the given user
     *
     * @param usermail {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(AuthConstants.CHECK_FOR_MFA)
    @Operation(summary = "CHECK FOR MFA", description = "REST API responsible to check if MFA is enabled for the given user")
    public ResponseEntity<BaseResponse> checkForMfa(
            @Parameter(description = "EmailId value to check for MFA of corresponding user", required = true) @PathVariable(RequestParams.MAIL_ID) String usermail
    ) {
        String method = "checkForMfa";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        UserAccountDto userAccountDto = new UserAccountDto();
        Boolean is2faEnabled = authService.checkForMfa(usermail);
        userAccountDto.setMfaStatus(is2faEnabled);
        baseResponse.setSuccess(true);
        baseResponse.setMessage("MFA Status Fetched Successfully");
        baseResponse.setPayload(userAccountDto);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to logout a user
     *
     * @return {@link BaseResponse}
     */
    @GetMapping(AuthConstants.LOGOUT)
    @Operation(summary = "LOGOUT", description = "REST API responsible to logout a user")
    public ResponseEntity<BaseResponse> logout(HttpServletRequest request) {
        String method = "logout";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        String token = requestUtil.extractJwtFromRequest(request);
        ResponseEntity<String> usernameResponse = tokenService.getUsernameFromToken(token);
        String username = usernameResponse.getBody();
        authService.invalidateExistingRefreshToken(username);
        baseResponse.setMessage("User logged out!");
        baseResponse.setSuccess(true);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to check if MFA is enabled for the given user
     *
     * @param request {@link HttpServletRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(AuthConstants.CHECK_MFA)
    @Operation(summary = "CHECK MFA", description = "REST API responsible to check if MFA is enabled for the given user")
    public ResponseEntity<BaseResponse> checkMfa(HttpServletRequest request) {
        String method = "checkMfa";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        UserAccountDto userAccountDto = new UserAccountDto();
        Boolean is2faEnabled = authService.checkMfa(request);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        userAccountDto.setMfaStatus(is2faEnabled);
        baseResponse.setSuccess(true);
        baseResponse.setMessage("Status Fetched Successfully");
        baseResponse.setPayload(userAccountDto);
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to check if provided access token is valid
     *
     * @param request {@link HttpServletRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(AuthConstants.VALIDATE_ACCESS_TOKEN)
    @Operation(summary = "VALIDATE ACCESS TOKEN", description = "REST API responsible to check if provided access token is valid")
    public ResponseEntity<BaseResponse> validateAccessToken(HttpServletRequest request) {
        String method = "validateAccessToken";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse authTokenResponse = authService.validateAccessToken(request);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(authTokenResponse, HttpStatus.OK);
    }

    /**
     * REST API to generate Internal Access token
     *
     * @param userId      {@link String}
     * @param secretToken {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(AuthConstants.GENERATE_INTERNAL_TOKEN)
    @Operation(summary = "INTERNAL EXTERNAL TOKEN", description = "REST API responsible to generate Internal token")
    public ResponseEntity<BaseResponse> generateInternalToken(
            @Parameter(description = "UserId value to generate Internal token for corresponding user", required = true) @RequestParam(RequestParams.USER_ID) String userId,
            @Parameter(description = "X-secret token", required = true) @RequestHeader(HttpHeaderConstants.X_SECRET) String secretToken
    ) {
        String method = "generateInternalToken";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = authService.generateInternalToken(userId, secretToken);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return RestUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to check checkSecurityQuestions if is enabled for the given user
     *
     * @param request {@link HttpServletRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(AuthConstants.CHECK_SQ)
    @Operation(summary = "CHECK SECURITY QUESTION", description = " REST API responsible to check Security Questions if is enabled for the given user")
    public ResponseEntity<BaseResponse> checkSQEnable(HttpServletRequest request) {
        String method = "checkSQEnable";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        SecurityQuestionsResponse securityQuestionsResponse = new SecurityQuestionsResponse();
        Boolean isSQEnabled = authService.checkSQ(request);
        securityQuestionsResponse.setSqStatus(isSQEnabled);
        baseResponse.setPayload(securityQuestionsResponse);
        baseResponse.setSuccess(true);
        baseResponse.setMessage("Status Fetched Successfully");
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to check if Security Question is enabled for the given user
     *
     * @param username {@link String}
     * @return {@link Boolean}
     */
    @GetMapping(AuthConstants.CHECK_FOR_SQ)
    @Operation(summary = "CHECK FOR SECURITY QUESTION", description = "REST API responsible to check if Security Question is enabled for the given user")
    public ResponseEntity<BaseResponse> checkForSecurityQuestions(
            @Parameter(description = "Username value to check for security questions of corresponding user", required = true) @PathVariable(RequestParams.USERNAME) String username
    ) {
        String method = "checkForSecurityQuestions";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = authService.checkForSQ(username);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to save Security Question
     *
     * @param request             {@link HttpServletRequest}
     * @param securityQuesRequest {@link SecurityQuesRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(AuthConstants.SECURITY_QUESTIONS)
    @Operation(summary = "SECURITY QUESTIONS", description = "REST API responsible to save Security Question")
    public ResponseEntity<BaseResponse> saveSecurityQuestions(
            HttpServletRequest request,
            @RequestBody SecurityQuesRequest securityQuesRequest
    ) {
        String method = "saveSecurityQuestions";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = authService.saveSecurityQuestion(request, securityQuesRequest);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);

    }

    /**
     * REST API responsible to return list of Security Question
     *
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(AuthConstants.SECURITY_QUESTIONS)
    @Operation(summary = "SECURITY QUESTIONS", description = "REST API responsible to return list of Security Questions")
    public ResponseEntity<BaseResponse> getSecurityQuestions() {
        String method = "getSecurityQuestions";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = authService.getSecurityQuestions();
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * @param username            {@link String}
     * @param securityQuesRequest {@link }
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(AuthConstants.VALIDATE_SECURITY_QUESTION)
    @Operation(summary = "VALIDATE SECURITY QUESTION", description = "REST API responsible to verify Security Questions")
    public ResponseEntity<BaseResponse> checkSecurityQuestion(
            @Parameter(description = "Username value to verify security question of corresponding user", required = true) @RequestParam(RequestParams.USERNAME) String username,
            @RequestBody SecurityQuesRequest securityQuesRequest) {
        String method = "checkSecurityQuestion";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = authService.checkSecurityQuestion(username, securityQuesRequest);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);

    }

    /**
     * REST API responsible to do Security checks
     *
     * @param username      {@link String}
     * @param fetchResponse {@link FetchResponse}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(AuthConstants.SECURITY_CHECKS + PathVariables.USERNAME_PARAM1)
    @Operation(summary = "SECURITY_CHECKS", description = "REST API responsible to do Security checks")
    public ResponseEntity<BaseResponse> securityChecks(
            @Parameter(description = "Username value to verify security question of corresponding user", required = true) @PathVariable(RequestParams.USERNAME) String username,
            @RequestBody FetchResponse fetchResponse) {
        String method = "securityChecks";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = authService.securityChecks(username, fetchResponse);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to increment failed attempts
     *
     * @param id            {@link Integer}
     * @param fetchResponse {@link FetchResponse}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(AuthConstants.INCREMENT_FAILED_ATTEMPTS + PathVariables.ID_PARAM)
    @Operation(summary = "INCREMENT FAILED ATTEMPTS", description = "REST API responsible to increment failed attempts")
    public ResponseEntity<BaseResponse> incrementFailedAttempts(
            @Parameter(description = "UserId value to increment failed attempts of corresponding user", required = true) @PathVariable("id") String id,
            @RequestBody FetchResponse fetchResponse) {
        String method = "incrementFailedAttempts";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = authService.incrementFailedAttempts(id, fetchResponse);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to reset failed attempts
     *
     * @param id {@link Integer}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(AuthConstants.RESET_FAILED_ATTEMPTS + PathVariables.ID_PARAM)
    @Operation(summary = "RESET FAILED ATTEMPTS", description = "REST API responsible to reset failed attempts")
    public ResponseEntity<BaseResponse> resetFailedAttempts(
            @Parameter(description = "UserId value to reset failed attempts of corresponding user", required = true) @PathVariable("id") String id) {
        String method = "resetFailedAttempts";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = authService.resetFailedAttempts(id);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to authenticate OTP code
     *
     * @param httpServletRequest {@link HttpServletRequest}
     * @param passcode           {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(AuthConstants.AUTHENTICATE_PASSCODE)
    @Operation(summary = "AUTHENTICATE OTP PASSCODE FOR MODERATE RISK USER AUTHENTICATION", description = "REST API responsible to authenticate otp passcode for moderate risk user")
    public ResponseEntity<BaseResponse> authenticateOtpPasscode(
            HttpServletRequest httpServletRequest, @Parameter(description = "Email of user whose passcode is to be verified", required = true) @RequestParam(RequestParams.MAIL_ID) String usermail,
            @Parameter(description = "Email of user whose passcode is to be verified", required = true) @RequestParam(RequestParams.PASSCODE) String passcode
    ) {
        String method = "authenticateOtpPasscode";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = authService.authenticateOtpPasscode(httpServletRequest, usermail, passcode);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to check if entered password is correct user
     *
     * @param httpServletRequest   {@link HttpServletRequest}
     * @param passwordCheckRequest {@link PasswordCheckRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(AuthConstants.CHECK_FOR_PASSWORD)
    @Operation(summary = "CHECK FOR PASSWORD", description = "REST API responsible to check if password entered is correct for the given user")
    public ResponseEntity<BaseResponse> checkForPassword(
            HttpServletRequest httpServletRequest,
            @RequestBody PasswordCheckRequest passwordCheckRequest
    ) {
        String method = "checkForPassword";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = authService.checkForPassword(httpServletRequest, passwordCheckRequest.getCurrentPassword());
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to generate new access token if refresh token is valid
     *
     * @param request {@link HttpServletRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(AuthConstants.GENERATE_NEW_ACCESS_TOKEN)
    @Operation(summary = "GENERATE NEW ACCESS TOKEN IF REFRESH TOKEN IS VALID", description = "REST API responsible to generate new access token if refresh token is valid")
    public ResponseEntity<BaseResponse> generateNewAccessToken(@Parameter(description = "Refresh Token to generate new access token for the user", required = true) @PathVariable(RequestParams.REFRESH_TOKEN) String refreshToken, HttpServletRequest request, @RequestBody AuthRequest authRequest) {
        String method = "generateNewAccessToken";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, AUTH_CONTROLLER_CLASS, method);
        long startTime = System.currentTimeMillis();
        BaseResponse authTokenResponse = authService.generateNewAccessToken(request, refreshToken, authRequest);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTH_CONTROLLER_CLASS, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(authTokenResponse, HttpStatus.OK);
    }
}
