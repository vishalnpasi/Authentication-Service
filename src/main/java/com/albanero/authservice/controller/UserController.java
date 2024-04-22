package com.albanero.authservice.controller;

import com.albanero.authservice.common.constants.MappingConstants;
import com.albanero.authservice.common.constants.PathVariables;
import com.albanero.authservice.common.constants.RequestParams;
import com.albanero.authservice.common.constants.UserMappingConstants;
import com.albanero.authservice.common.dto.request.*;
import com.albanero.authservice.common.dto.response.BaseResponse;
import com.albanero.authservice.common.dto.response.ResetPasswordResponse;
import com.albanero.authservice.common.dto.response.UserAccountDto;
import com.albanero.authservice.common.util.HelperUtil;
import com.albanero.authservice.common.util.RestUtil;
import com.albanero.authservice.model.UserProfile;
import com.albanero.authservice.model.UserSession;
import com.albanero.authservice.repository.UserRepository;
import com.albanero.authservice.service.AuthenticationService;
import com.albanero.authservice.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import jakarta.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.util.List;

import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_END_LOG_TAG;
import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_START_LOG_TAG;
import static com.albanero.authservice.common.constants.PathVariables.*;
import static com.albanero.authservice.common.constants.RequestParams.*;

/**
 * Class that provide User end points mappings.
 *
 * @author arunima.mishra
 */
@RestController
@RequestMapping(MappingConstants.API_USER_BASE)
public class UserController {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserController.class);

    private static final String USER_CONTROLLER = "UserController";

    private final UserDetailsService userDetailsService;

    private final UserService userService;

    private final AuthenticationService authService;

    private final UserRepository userRepo;

    private final HelperUtil helperUtil;

    @Autowired
    public UserController(UserDetailsService userDetailsService, UserService userService, UserRepository userRepo,
                          HelperUtil helperUtil, AuthenticationService authService) {
        this.userDetailsService = userDetailsService;
        this.userService = userService;
        this.userRepo = userRepo;
        this.helperUtil = helperUtil;
        this.authService = authService;
    }

    /**
     * REST API responsible to register a new user
     *
     * @param user    {@link RegistrationUser}
     * @param request {@link HttpServletRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(UserMappingConstants.USER)
    @Operation(summary = "REGISTER USER", description = "REST API responsible to register a new user")
    public ResponseEntity<BaseResponse> saveUser(@RequestBody RegistrationUser user, HttpServletRequest request){
        String method = "saveUser";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
			long startTime = System.currentTimeMillis();
			BaseResponse baseResponse = userService.save(user, request);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
			return ResponseEntity.ok(baseResponse);
	}

    /**
     * REST API responsible to generate/regenerate new MFA QR link and secret
     *
     * @param user {@link RegistrationUser}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(UserMappingConstants.GENERATE_MFA_QR_AND_SECRET)
    @Operation(summary = "GENERATE MFA QR AND SECRET", description = "REST API responsible to update and save mfa for that user")
    public ResponseEntity<BaseResponse> generateMfaQrAndSecret(HttpServletRequest request ,@RequestBody RegistrationUser user) {
        String method = "generateMfaQrAndSecret";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.generateMfaQrAndSecret(request,user);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to verify user email
     *
     * @param code {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.VERIFY_USER)
    @Operation(summary = "VERIFY USER", description = "REST API responsible to verify user email")
    public ResponseEntity<BaseResponse> verifyUser(
            @Parameter(description = "Code used to verify user", required = true) @RequestParam("code") String code) {
        String method = "verifyUser";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        if (userService.verify(code)) {
            baseResponse.setMessage("User verified.");
            baseResponse.setSuccess(true);
            LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
            return ResponseEntity.ok(baseResponse);
        } else {
            baseResponse.setMessage("Failed to verify user.");
            baseResponse.setSuccess(false);
            return new ResponseEntity<>(baseResponse, HttpStatus.OK);
        }
    }

    /**
     * REST API responsible to resend verification link
     *
     * @param email   {@link String}
     * @param request {@link HttpServletRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.RESEND_VERIFICATION_LINK)
    @Operation(summary = "RESEND VERIFICATION LINK", description = "REST API responsible to resend verification link")
    public ResponseEntity<BaseResponse> resendVerificationEmail(
            @Parameter(description = "Email to which link will be sent", required = true) @RequestParam("email") String email,
            HttpServletRequest request
    ) {
        String method = "resendVerificationEmail";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.resendVerificationLink(request, email);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to approve user
     *
     * @param code    {@link String}
     * @param request {@link HttpServletRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.REQUEST_USER_APPROVAL)
    @Operation(summary = "REQUEST USER APPROVAL", description = "REST API responsible to approve user")
    public ResponseEntity<BaseResponse> requestForAccountApproval(
            @Parameter(description = "Code used to verify user", required = true) @RequestParam("code") String code,
            HttpServletRequest request
    ) {
        String method = "requestForAccountApproval";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.requestForAccountApproval(request, code);

        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to approve user
     *
     * @param email            {@link String}
     * @param registrationUser {@link RegistrationUser}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(UserMappingConstants.APPROVE_USER)
    @Operation(summary = "APPROVE USER", description = "REST API responsible to approve user")
    public BaseResponse approveUser(
            @Parameter(description = "Email used to approve user", required = true) @RequestParam("email") String email,
            @RequestParam("isAccountApproved") Boolean isAccountApproved, @RequestBody RegistrationUser registrationUser
    ) {
        String method = "approveUser";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.approve(email, isAccountApproved, registrationUser);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return baseResponse;
    }

    /**
     * REST API responsible to change user account status (approve/deactivate/unblock)
     *
     * @param userAccountStatus {@link UserAccountStatus}
     * @param request           {@link HttpServletRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PutMapping(UserMappingConstants.CHANGE_USERS_ACCOUNT_STATUS)
    @Operation(summary = "CHANGE_USERS_ACCOUNT_STATUS", description = "REST API responsible to change multiple users account status")
    public ResponseEntity<BaseResponse> changeUserAccountStatus(@RequestBody UserAccountStatus userAccountStatus, HttpServletRequest request) {
        String method = "changeUserAccountStatus";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.changeUserAccountStatus(userAccountStatus, request);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to register or login a user via Google
     *
     * @param user {@link RegistrationUser}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(UserMappingConstants.GOOGLE_AUTH_USER)
    @Operation(summary = "GOOGLE AUTH USER", description = "REST API responsible to register or login a user via Google")
    public ResponseEntity<BaseResponse> registerForGoogle(@RequestBody RegistrationUser user) {
        String method = "registerForGoogle";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.registerForGoogleLogin(user);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);
    }

    /**
     * REST API responsible to save a new pass-code
     *
     * @param mailId                {@link String}
     * @param resetPasswordResponse {@link ResetPasswordResponse}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(UserMappingConstants.ADD_PASSCODE)
    @Operation(summary = "ADD PASSCODE", description = "REST API responsible to save a new pass-cod")
    public ResponseEntity<BaseResponse> addPasscode(
            @Parameter(description = "Email of user whose passcode is to be saved", required = true) @PathVariable(RequestParams.MAIL_ID) String mailId,
            @RequestBody ResetPasswordResponse resetPasswordResponse) {
        String method = "addPasscode";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.addPasscode(mailId, resetPasswordResponse.getPasscode());
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);
    }

    /**
     * REST API responsible to validate existing pass-code
     *
     * @param mailId   {@link String}
     * @param passcode {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.CHECK_PASSCODE)
    @Operation(summary = "CHECK PASSCODE", description = "REST API responsible to validate existing pass-code")
    public ResponseEntity<BaseResponse> checkPasscode(
            @Parameter(description = "Email of user whose passcode is to be verified", required = true) @PathVariable(RequestParams.MAIL_ID) String mailId,
            @PathVariable(RequestParams.PASSCODE) String passcode) {
        String method = "checkPasscode";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.checkPasscode(mailId, passcode);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);
    }

    /**
     * REST API responsible to save new password
     *
     * @param changePasswordRequest {@link ChangePasswordRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(UserMappingConstants.ADD_PASSWORD)
    @Operation(summary = "ADD PASSWORD", description = "REST API responsible to save new password")
    public ResponseEntity<BaseResponse> setPassword(@RequestBody ChangePasswordRequest changePasswordRequest) {
        String method = "setPassword";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.savePassword(changePasswordRequest);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return RestUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to validate an existing user
     *
     * @param username {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.VALIDATE_USER)
    @Operation(summary = "VALIDATE USER FOR GOOGLE LOGIN", description = "REST API responsible to validate an existing user")
    public ResponseEntity<BaseResponse> validateUserForGLogin(
            @Parameter(description = "Username value to verify corresponding user", required = true) @PathVariable(RequestParams.USERNAME) String username) {
        String method = "validateUserForGLogin";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.validateUserForGLogin(username);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);
    }

    /**
     * REST API responsible to update an existing user
     *
     * @param user    {@link RegistrationUser}
     * @param request {@link HttpServletRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PutMapping(UserMappingConstants.USER_PROFILE)
    @Operation(summary = "UPDATE USER", description = "REST API responsible to update an existing user")
    public ResponseEntity<BaseResponse> updateUser(@RequestBody RegistrationUser user, HttpServletRequest request) {
        String method = "updateUser";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.updateUser(request, user);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to fetch user profile details
     *
     * @param request     {@link HttpServletRequest}
     * @param authRequest {@link AuthenticationRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(UserMappingConstants.USER_PROFILE)
    @Operation(summary = "USER PROFILE DETAILS", description = "REST API responsible to fetch user profile details")
    public ResponseEntity<BaseResponse> getUser(HttpServletRequest request, @RequestBody AuthRequest authRequest) {
        String method = "getUser";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.getUser(request, authRequest);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);
    }

    /**
     * REST API responsible to delete an existing user
     *
     * @param id {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @DeleteMapping(UserMappingConstants.USER + PathVariables.ID_PARAM)
    @Operation(summary = "DELETE USER", description = "REST API responsible to delete an existing user")
    public ResponseEntity<BaseResponse> deleteUser(
            @Parameter(description = "UserId value to delete corresponding user", required = true) @PathVariable("id") String id) {
        String method = "deleteUser";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.deleteUser(id);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);
    }


    /**
     * REST API responsible to update mfa for that user
     *
     * @param request {@link HttpServletRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.UPDATE_MFA)
    @Operation(summary = "UPDATE MFA", description = "REST API responsible to update mfa for that user")
    public ResponseEntity<BaseResponse> getQrFor2FA(HttpServletRequest request) throws UnsupportedEncodingException {
        String method = "getQrFor2FA";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.updateUser2FA(request);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);
    }

    /**
     * REST API responsible to update and save mfa for that user
     *
     * @param authRequest {@link AuthenticationRequest}
     * @param request     {@link HttpServletRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PutMapping(UserMappingConstants.UPDATE_MFA)
    @Operation(summary = "UPDATE AND SAVE MFA", description = "REST API responsible to update and save mfa for that user")
    public ResponseEntity<BaseResponse> modifyAndSaveUser2FA(@RequestBody AuthRequest authRequest, HttpServletRequest request) {
        String method = "modifyAndSaveUser2FA";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.updateAndSaveUser2FA(
                authRequest.getUses2FA(),
                authRequest.getMfaSecret(),
                request
        );
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);
    }

    /**
     * REST API responsible to find user by username
     *
     * @param username {@link String}
     * @return {@link ResponseEntity<UserProfile>}
     */
    @GetMapping(UserMappingConstants.USER_PROFILE_DETAILS + PathVariables.USERNAME_PARAM1)
    @Operation(summary = "GET USER BY USERNAME", description = "REST API responsible to find user by username")
    public ResponseEntity<UserProfile> getUserByUsername(
            @Parameter(description = "Username value to fetch corresponding user", required = true) @PathVariable(RequestParams.USERNAME) String username) {
        String method = "getUserByUsername";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        UserProfile user = userRepo.findByUsername(username);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(user, HttpStatus.OK);
    }

    /**
     * REST API responsible to save resfreshToken in database
     *
     * @param userSession {@link UserSession}
     * @return {{@link ResponseEntity<BaseResponse>}
     */

    @PostMapping(UserMappingConstants.SAVER_TOKEN)
    @Operation(summary = "SAVE REFRESH TOKEN", description = "REST API responsible to save resfreshToken")
    public ResponseEntity<BaseResponse> saveRefreshToken(@RequestBody UserSessionRequestDto userSession) {
        String method = "saveRefreshToken";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        UserSession userSessionResponse = userService.saveRToken(userSession);
        baseResponse.setMessage("Refresh Token saved");
        baseResponse.setSuccess(true);
        baseResponse.setPayload(userSessionResponse);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to get User by Email Details
     *
     * @param mail {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.USERMAIL + PathVariables.MAIL_ID_PARAM)
    @Operation(summary = "GET USER BY EMAIL", description = "REST API responsible to get User by Email Details")
    public ResponseEntity<BaseResponse> getUserByEmail(
            @Parameter(description = "EmailId value to fetch corresponding user", required = true) @PathVariable(RequestParams.MAIL_ID) String mail) {
        String method = "getUserByEmail";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        BaseResponse baseResponse = new BaseResponse();
        long startTime = System.currentTimeMillis();
        UserProfile user = authService.loadUserProfileByMailId(mail);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        baseResponse.setMessage("User details Fetched");
        baseResponse.setSuccess(true);
        baseResponse.setPayload(user);
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to check if a user exists with the given username
     *
     * @param username {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.VERIFY_USERNAME)
    @Operation(summary = "VERIFY USERNAME", description = "REST API responsible to check if a user exists with the given username")
    public ResponseEntity<BaseResponse> verifyUsername(
            @Parameter(description = "Username value to check existence of corresponding user", required = true) @PathVariable(RequestParams.USERNAME) String username) {
        String method = "verifyUsername";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        UserAccountDto userAccountDto = new UserAccountDto();
        boolean isValidUsername = helperUtil.isValidUsername(username);
        boolean isValidEmail = helperUtil.isValidEmail(username);
        boolean duplicateUsername = helperUtil.checkForDuplicateUsername(username);
        userAccountDto.setValidUserName((isValidUsername && !duplicateUsername) || (isValidEmail && !duplicateUsername));
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        baseResponse.setPayload(userAccountDto);
        baseResponse.setSuccess(true);
        baseResponse.setMessage("Status Fetched Successfully");
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to check if a user exists with the given mail
     *
     * @param email {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.VERIFY_EMAIL)
    @Operation(summary = "VERIFY EMAIL", description = "REST API responsible to check if a user exists with the given mail")
    public ResponseEntity<BaseResponse> verifyEmail(
            @Parameter(description = "EmailId value to check existence of corresponding user", required = true) @PathVariable(RequestParams.MAIL_ID) String email) {
        String method = "verifyEmail";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        UserAccountDto userAccountDto = new UserAccountDto();
        boolean isValidEmail = helperUtil.isValidEmail(email);
        boolean duplicateEmail = helperUtil.checkForDuplicateEmail(email);
        userAccountDto.setValidEmail(isValidEmail && !duplicateEmail);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        baseResponse.setPayload(userAccountDto);
        baseResponse.setSuccess(true);
        baseResponse.setMessage("status fetched successfully");
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to change password of user with the given mail
     *
     * @param request {@link ChangePasswordRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(UserMappingConstants.CHANGE_PASSWORD)
    @Operation(summary = "CHANGE PASSWORD", description = "REST API responsible to change password of user with the given mail")
    public ResponseEntity<BaseResponse> changePassword(@RequestBody ChangePasswordRequest request) {
        String method = "changePassword";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.changePassword(
                request.getToken(),
                request.getOldPassword(),
                request.getNewPassword(),
                request.getConfirmedPassword()
        );
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to verify user access
     *
     * @param request   {@link HttpServletRequest}
     * @param productId {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.VERIFY_USER_ACCESS)
    @Operation(summary = "VERIFY USER ACCESS", description = "REST API responsible to verify user access")
    public ResponseEntity<BaseResponse> verifyUserAccess(HttpServletRequest request, String productId) {
        String method = "verifyUserAccess";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        UserAccountDto userAccountDto = new UserAccountDto();
        Boolean isAccessAllowed = userService.verifyUserAccess(request, productId);
        userAccountDto.setUserAccess(isAccessAllowed);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        baseResponse.setSuccess(true);
        baseResponse.setMessage("User access status fetched");
        baseResponse.setPayload(userAccountDto);
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }


    /**
     * REST API responsible to provide username corresponding to the given user ID
     *
     * @param request {@link HttpServletRequest}
     * @param userId  {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.FETCH_USERNAME)
    @Operation(summary = "FETCH USERNAME", description = "REST API responsible to provide username corresponding to the given user ID")
    public ResponseEntity<BaseResponse> fetchUsername(
            HttpServletRequest request,
            @Parameter(description = "UserId value to fetch corresponding username", required = true) @PathVariable(USER_ID) String userId
    ) {
        String method = "fetchUsername";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse authTokenResponse = userService.fetchUsername(request, userId);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(authTokenResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to get product details
     *
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.PRODUCT_DETAILS)
    @Operation(summary = "PRODUCT DETAILS", description = "REST API responsible to get product details")
    public ResponseEntity<BaseResponse> getAllProductDetails(HttpServletRequest request) {
        String method = "getAllProductDetails";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.getProductDetails(request);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);
    }

    /**
     * REST API responsible to provide UserDetails object corresponding to the given
     * username
     *
     * @param username {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.USER_DETAILS + PathVariables.USERNAME_PARAM1)
    @Operation(summary = "USER DETAILS", description = "REST API responsible to provide UserDetails object corresponding to the given username")
    public ResponseEntity<BaseResponse> getUserDetailsObject(@PathVariable String username) {
        String method = "getUserDetailsObject";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        if (username != null && !username.isEmpty()) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            baseResponse.setPayload(userDetails);
            LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
            return new ResponseEntity<>(baseResponse, HttpStatus.OK);
        }
        return new ResponseEntity<>(baseResponse, HttpStatus.BAD_REQUEST);
    }

    /**
     * REST API responsible to provide user email
     *
     * @param request {@link HttpServletRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.FETCH_EMAIL)
    @Operation(summary = "FETCH EMAIL", description = "REST API responsible to provide user email")
    public ResponseEntity<BaseResponse> fetchEmail(HttpServletRequest request) {
        String method = "fetchEmail";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse emailResponse = new BaseResponse();
        String email = userService.fetchEmail(request);
        if (email != null) {
            emailResponse.setPayload(email);
            emailResponse.setSuccess(true);
            emailResponse.setMessage("Successfully fetched email.");
            LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
            return new ResponseEntity<>(emailResponse, HttpStatus.OK);
        }
        emailResponse.setSuccess(false);
        emailResponse.setMessage("Email does not exist for this user!");
        return new ResponseEntity<>(emailResponse, HttpStatus.NOT_FOUND);
    }

    /**
     * REST API responsible to upload a profile picture of user
     *
     * @param request {@link HttpServletRequest}
     * @param image   {@link MultipartFile}
     * @return {@link ResponseEntity<BaseResponse>}
     */

    @PostMapping(UserMappingConstants.PROFILE_IMAGE)
    @Operation(summary = "PROFILE IMAGE", description = "REST API responsible to upload a profile picture of user")
    public ResponseEntity<BaseResponse> profilePic(
            HttpServletRequest request,
            @Parameter(description = "Picture which is to added as profile picture", required = true) @RequestParam(RequestParams.IMAGE) MultipartFile image
    ) {
        String method = "profilePic";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.uploadProfilePicture(request, image);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to save new Security question
     *
     * @param changeSQRequest {@link ChangePasswordRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(UserMappingConstants.ADD_SQ)
    @Operation(summary = "ADD SQ", description = "REST API responsible to save new question")
    public ResponseEntity<BaseResponse> setSQ(@RequestBody ChangeSQRequest changeSQRequest) {
        String method = "setSQ";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.saveSQ(changeSQRequest);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);
    }


    /**
     * REST API responsible to compare passwords
     *
     * @param request              {@link HttpServletRequest}
     * @param passwordCheckRequest {@link PasswordCheckRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(UserMappingConstants.CHECK_PASSWORD)
    @Operation(summary = "CHECK_PASSWORD", description = "REST API responsible to compare passwords")
    public ResponseEntity<BaseResponse> checkPassword(
            HttpServletRequest request,
            @RequestBody PasswordCheckRequest passwordCheckRequest
    ) {
        String method = "checkPassword";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.checkPassword(request, passwordCheckRequest.getCurrentPassword());
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to delete an existing Change security Settings
     *
     * @param id {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @DeleteMapping(UserMappingConstants.DELETE_SECURITY_SETTINGS + PathVariables.ID_PARAM)
    @Operation(summary = "DELETE USER", description = "REST API responsible to delete an existing Change security Settings document")
    public ResponseEntity<BaseResponse> deleteChangeSecuritySettings(
            @Parameter(description = "UserId value to delete corresponding Change security Settings", required = true) @PathVariable("id") String id) {
        String method = "deleteChangeSecuritySettings";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.deleteChangeSecuritySettings(id);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);
    }

    /**
     * REST API responsible to provide user details corresponding to the given user ID
     *
     * @param userId {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.USER + PathVariables.USER_ID_PARAM)
    @Operation(summary = "FETCH USERNAME", description = "REST API responsible to provide user details corresponding to the given user ID")
    public ResponseEntity<BaseResponse> fetchUserDetails(@Parameter(description = "UserId value to fetch corresponding user details", required = true) @PathVariable(USER_ID) String userId,
                                                         HttpServletRequest httpServletRequest) {
        String method = "fetchUserDetails";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse authTokenResponse = userService.fetchUserDetailsFromUserId(userId, httpServletRequest);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(authTokenResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to provide fetch user details corresponding to the given userIds
     *
     * @param userIds {@link List<String>}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(UserMappingConstants.USERS)
    @Operation(summary = "FETCH USERNAME", description = "REST API responsible to provide username corresponding to the given set of user IDs")
    public ResponseEntity<BaseResponse> fetchUserDetailsList(@RequestBody(required = false) List<String> userIds) {
        String method = "fetchUserDetailsList";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse userDetailsListResponse = userService.fetchUserDetailsList(userIds);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(userDetailsListResponse, HttpStatus.OK);
    }

    /**
     * Api to request ip unblock for user
     *
     * @param request          {@link HttpServletRequest}
     * @param registrationUser {@link RegistrationUser}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(UserMappingConstants.REQUEST_UNBLOCK)
    @Operation(summary = "REQUEST UNBLOCK", description = "REST API responsible to send email to request unblock of a user")
    public ResponseEntity<BaseResponse> requestUnblock(
            HttpServletRequest request,
            @RequestBody(required = true) RegistrationUser registrationUser
    ) {
        String method = "requestUnblock";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse userDetailsListResponse = userService.unblockUserRequest(request, registrationUser);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(userDetailsListResponse, HttpStatus.OK);
    }

    /**
     * Api to unblock the ip of a  user
     *
     * @param registrationUser {@link RegistrationUser}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(UserMappingConstants.UNBLOCK_USER)
    @Operation(summary = "UNBLOCK USER", description = "REST API responsible to unblock user")
    public ResponseEntity<BaseResponse> unblockUser(@RequestBody RegistrationUser registrationUser) throws UnsupportedEncodingException {
        String method = "unblockUser";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.unblockUser(registrationUser);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible to provide username from token
     *
     * @param httpServletRequest {@link HttpServletRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(UserMappingConstants.FETCH_USERNAME_FROM_TOKEN)
    @Operation(summary = "FETCH USERNAME", description = "REST API responsible to provide user details corresponding to the given user ID")
    public ResponseEntity<BaseResponse> fetchUserNameFromToken(HttpServletRequest httpServletRequest) {
        String method = "fetchUserNameFromToken";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.fetchUserNameFromToken(httpServletRequest);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }


    /**
     * Rest API responsible to provide role of a user in project
     *
     * @param projectId {@link String}
     * @param userId    {@link String}
     */
    @GetMapping(UserMappingConstants.USER_ROLE + PROJECT_ID_PARAM + USER_ID_PARAM)
    public ResponseEntity<BaseResponse> fetchUserDetailsByUsernameAndProjectId(
            @PathVariable(PROJECT_ID) String projectId,
            @PathVariable(USER_ID) String userId
    ) {
        String method = "fetchUserDetailsByUserIdAndProjectId";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.fetchUserDetailsByUserIdAndProjectId(projectId, userId);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * Rest API responsible to change default role of a user in project
     *
     * @param projectOrgRoleId {@link String}
     */
    @GetMapping(UserMappingConstants.SET_DEFAULT_PROJECT_ROLE  + PROJECT_ORG_ROLE_ID_PARAM)
    public ResponseEntity<BaseResponse> setDefaultProjectOrgRole(
            @PathVariable(PROJECT_ORG_ROLE_ID) String projectOrgRoleId
    ) {
        String method = "setDefaultProjectOrgRole";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userService.setDefaultProjectOrgRole(projectOrgRoleId);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

}

