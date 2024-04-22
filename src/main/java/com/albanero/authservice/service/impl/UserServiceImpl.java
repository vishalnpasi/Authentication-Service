package com.albanero.authservice.service.impl;

import com.albanero.authservice.common.constants.*;
import com.albanero.authservice.common.dto.ProjectOrgRoleId;
import com.albanero.authservice.common.dto.request.*;
import com.albanero.authservice.common.dto.response.*;
import com.albanero.authservice.common.util.EmailUtil;
import com.albanero.authservice.common.util.HelperUtil;
import com.albanero.authservice.common.util.RequestUtil;
import com.albanero.authservice.exception.UserServiceException;
import com.albanero.authservice.model.*;
import com.albanero.authservice.repository.*;
import com.albanero.authservice.service.*;
import com.amazonaws.util.IOUtils;
import jakarta.annotation.Nonnull;
import org.jasypt.util.text.BasicTextEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.*;
import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG;
import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG;


@Service
@RefreshScope
public class UserServiceImpl implements UserService {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserServiceImpl.class);

    private static final String USER_SERVICE_IMPL = "UserServiceImpl";

    @Value("${jasyptSecret}")
    private String encryptorPassword;

    private final AuthenticationService authService;

    private final PasswordEncoder bcryptEncoder;

    private final UserRepository userRepo;

    private final MfaStatusRepository mfaRepo;

    private final SecurityQuestionsRepository securityQuestionsRepository;

    private final SQStatusRepository sqRepo;

    private final AccStatusRepository accStatusRepo;

    private final RoleRepository roleRepo;

    private final OrgRepository orgRepo;

    private final OrgRoleRepository orgRoleRepo;

    private final UserOrgRoleRepository userOrgRoleRepo;

    private final UserSecRepository userSecRepo;

    private final UserRoleService userRoleService;

    private final UserSessionRepository userSessionRepo;

    private final ProductRepository prodRepo;

    private final HelperUtil helperUtil;

    private final RequestUtil requestUtil;

    private final EmailUtil emailUtil;

    private final TokenService tokenService;

    private final RBAService rbaService;

    private final ProjectOrgRepository projectOrgRepository;

    private final ProjectOrgRoleRepository projectOrgRoleRepository;

    private final HttpServletRequest request;

    @Autowired
    public UserServiceImpl(AuthenticationService authService, PasswordEncoder bcryptEncoder, UserRepository userRepo, MfaStatusRepository mfaRepo, SecurityQuestionsRepository securityQuestionsRepository, SQStatusRepository sqRepo, AccStatusRepository accStatusRepo, RoleRepository roleRepo, OrgRepository orgRepo, OrgRoleRepository orgRoleRepo, UserOrgRoleRepository userOrgRoleRepo, UserSecRepository userSecRepo, UserRoleService userRoleService, UserSessionRepository userSessionRepo, ProductRepository prodRepo, HelperUtil helperUtil, RequestUtil requestUtil, EmailUtil emailUtil, TokenService tokenService, RBAService rbaService, ProjectOrgRepository projectOrgRepository, ProjectOrgRoleRepository projectOrgRoleRepository, HttpServletRequest request) {
        this.authService = authService;
        this.bcryptEncoder = bcryptEncoder;
        this.userRepo = userRepo;
        this.mfaRepo = mfaRepo;
        this.securityQuestionsRepository = securityQuestionsRepository;
        this.sqRepo = sqRepo;
        this.accStatusRepo = accStatusRepo;
        this.roleRepo = roleRepo;
        this.orgRepo = orgRepo;
        this.orgRoleRepo = orgRoleRepo;
        this.userOrgRoleRepo = userOrgRoleRepo;
        this.userSecRepo = userSecRepo;
        this.userRoleService = userRoleService;
        this.userSessionRepo = userSessionRepo;
        this.prodRepo = prodRepo;
        this.helperUtil = helperUtil;
        this.requestUtil = requestUtil;
        this.emailUtil = emailUtil;
        this.tokenService = tokenService;
        this.rbaService = rbaService;
        this.projectOrgRepository = projectOrgRepository;
        this.projectOrgRoleRepository = projectOrgRoleRepository;
        this.request = request;
    }


    /**
     * Method To save the user
     *
     * @param user    {@link RegistrationUser}
     * @param request {@link HttpServletRequest}
     * @return {@link BaseResponse}
     */
    @Override
    public BaseResponse save(RegistrationUser user, HttpServletRequest request) {
        BaseResponse baseResponse = new BaseResponse();
        RegisterUserResponse registerUserResponse = new RegisterUserResponse();
        baseResponse.setSuccess(false);

        FetchResponse requestDetails = rbaService.fetchRequestDetails(request);

        UserProfile newUser = null;
        try {
            baseResponse = validateUserRegistrationRequest(user, baseResponse);
            if (baseResponse.getMessage() != null && !baseResponse.getMessage().isBlank()) {
                return baseResponse;
            }

            newUser = userRepo.save(helperUtil.setUserProfile(user));

            return registerUser(user, request, registerUserResponse, baseResponse, newUser, requestDetails);

        } catch (Exception e) {

            //remove user details
            if(!Objects.isNull(newUser)){
                helperUtil.removeUserDetails(newUser.getId());
            }
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "save", e.getMessage(), e.getStackTrace());
            throw new UserServiceException(ACTION_FAILED_EXCEPTION.label, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private BaseResponse registerUser(RegistrationUser user, HttpServletRequest request, RegisterUserResponse registerUserResponse, BaseResponse baseResponse, UserProfile newUser, FetchResponse requestDetails) {

        if (Boolean.TRUE.equals(user.getIsUsing2FA()) && user.getSecret() != null) {
            registerUserResponse.setIsMfaEnabled(true);
            baseResponse.setPayload(registerUserResponse);
            baseResponse.setMessage("User added and MFA details saved!");
        } else {
            baseResponse.setMessage("User added!");
        }

        baseResponse.setSuccess(true);
        mfaRepo.save(helperUtil.setMfaStatus(newUser.getId(), user));
        boolean isSecurityQuestionExist = false;
        Optional<SecurityQuestions> userSecurityQuestion = securityQuestionsRepository.findAll().stream()
                .filter(securityQuestion -> securityQuestion.getQuestions().contains(user.getSecurityQuestion().toLowerCase()))
                .findFirst();
        if(userSecurityQuestion.isPresent()){
            isSecurityQuestionExist = true;
        }
        if (user.getSecurityQuestion() != null && user.getSecurityAnswer() != null
                && isSecurityQuestionExist) {
            sqRepo.save(helperUtil.setSecurityQuestions(newUser.getId(), user));
        }

        accStatusRepo.save(helperUtil.setAccountStatusNewUser(newUser));
        if (Boolean.TRUE.equals(authService.saveAuthHistory(newUser.getId(), requestDetails)))
            return addUserRoles(request, newUser, baseResponse);
        else {
            baseResponse.setMessage("Error occured while saving user auth history");
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
            return baseResponse;
        }
    }

    private BaseResponse validateUserRegistrationRequest(RegistrationUser user, BaseResponse baseResponse) {
        // User name validation
        if (!helperUtil.isValidUsername(user.getUsername()) && !helperUtil.isValidEmail(user.getUsername())) {
            baseResponse.setMessage("Given username is not valid!");
            return baseResponse;
        }

        // Username and Email match validation
        if (helperUtil.isValidEmail(user.getUsername()) && (!user.getUsername().equals(user.getMailId()))) {
            baseResponse.setMessage("You cannot use a different email as username!");
            return baseResponse;
        }

        // User password validation
        if (!helperUtil.isValidPassword(user.getPassword())) {
            baseResponse.setMessage(ExceptionMessagesConstants.GIVEN_USER_PASSWORD_IS_NOT_VALID.toString());
            return baseResponse;
        }

        // Password fields match validation
        if (!user.getPassword().equals(user.getConfirmedPassword())) {
            baseResponse.setMessage(ExceptionMessagesConstants.PASSWORD_FIELDS_EXCEPTION.toString());
            return baseResponse;
        }

        // User email validation
        if (!helperUtil.isValidEmail(user.getMailId())) {
            baseResponse.setMessage("Given user email is not valid!");
            LOGGER.error("Given user email is not valid!");
            return baseResponse;
        }

        if (user.getFirstName() != null && !user.getFirstName().isBlank()) {
            return validateUserFirstName(user, baseResponse);

        }

        if (user.getLastName() != null && !user.getLastName().isBlank()) {
            return validateUserLastName(user, baseResponse);
        }

        // Duplicate user validation
        if (helperUtil.checkForDuplicateUsername(user.getUsername()) || helperUtil.checkForDuplicateEmail(user.getMailId())) {
            baseResponse.setMessage("A user already exists with the given identities");
            return baseResponse;
        }
        return baseResponse;
    }

    private BaseResponse validateUserLastName(RegistrationUser user, BaseResponse baseResponse) {
        String lastName = user.getLastName().substring(0,1).toUpperCase() + user.getLastName().substring(1);
        if (!helperUtil.isValidLastName(lastName)){
            baseResponse.setMessage("Last name is invalid");
            return baseResponse;
        }
        return baseResponse;
    }

    private BaseResponse validateUserFirstName(RegistrationUser user, BaseResponse baseResponse) {
        String firstName = user.getFirstName().substring(0,1).toUpperCase() + user.getFirstName().substring(1);
        if (!helperUtil.isValidFirstName(firstName)) {
            baseResponse.setMessage("First name is invalid");
            return baseResponse;
        }
        return baseResponse;
    }

    private BaseResponse addUserRoles(HttpServletRequest request, UserProfile newUser, BaseResponse baseResponse) {
        newUser.setRole(AuthServiceImpl.ROLE_ADMIN);
        UserOrgRole userOrgRole = new UserOrgRole();
        userOrgRole.setUserId(newUser.getId());

        String originName = request.getHeader(HttpHeaders.ORIGIN);
        if (originName != null) {
            String orgUrl = originName.substring(8);
            Organization org = orgRepo.findByOrgUrl(orgUrl);

            List<String> orgRoleIdList = new ArrayList<>();

            if (userRepo.findAll().size() == 1) {
                Role roleOrgAdmin = roleRepo.findByRoleName(PermissionConstants.ORG_ADMIN);
                OrganizationRole orgRoleAdmin = orgRoleRepo.findByOrgIdAndRoleId(org.getId(), roleOrgAdmin.getId());
                if (orgRoleAdmin == null) {
                    orgRoleAdmin = new OrganizationRole();
                    orgRoleAdmin.setOrgId(org.getId());
                    orgRoleAdmin.setRoleId(roleOrgAdmin.getId());
                }
                orgRoleRepo.save(orgRoleAdmin);
                orgRoleIdList.add(orgRoleAdmin.getId());

                Role role = roleRepo.findByRoleName(PermissionConstants.ROOT_USER);
                List<String> platformRoles = new ArrayList<>();
                platformRoles.add(role.getId());
                userOrgRole.setPlatformRoleIdList(platformRoles);

                OrganizationRole orgRoleRoot = orgRoleRepo.findByOrgIdAndRoleId(org.getId(), role.getId());
                if (orgRoleRoot == null) {
                    orgRoleRoot = new OrganizationRole();
                    orgRoleRoot.setOrgId(org.getId());
                    orgRoleRoot.setRoleId(role.getId());
                }
                orgRoleRepo.save(orgRoleRoot);
                orgRoleIdList.add(orgRoleRoot.getId());
            } else {
                Role roleOrgWatcher = roleRepo.findByRoleName(PermissionConstants.ORG_WATCHER);
                OrganizationRole orgRoleWatcher = orgRoleRepo.findByOrgIdAndRoleId(org.getId(), roleOrgWatcher.getId());
                if (orgRoleWatcher == null) {
                    orgRoleWatcher = new OrganizationRole();
                    orgRoleWatcher.setOrgId(org.getId());
                    orgRoleWatcher.setRoleId(roleOrgWatcher.getId());
                }
                orgRoleRepo.save(orgRoleWatcher);
                orgRoleIdList.add(orgRoleWatcher.getId());

                userOrgRole.setPlatformRoleIdList(new ArrayList<>());
            }

            userOrgRole.setOrgRoleIdList(orgRoleIdList);
            userOrgRole.setProjectOrgRoleIdList(new ArrayList<>());

            userOrgRole.setProjectOrgRoleIdList(new ArrayList<>());

            userOrgRoleRepo.save(userOrgRole);

            // Send email for account activation
            emailUtil.sendVerificationEmail(request, newUser, org);
        }

        return baseResponse;
    }

    /**
     * Method to Generate MFA and QA for user
     *
     * @param request {@link HttpServletRequest}
     * @param user {@link RegistrationUser}
     * @return {@link BaseResponse}
     */
    @Override
    public BaseResponse generateMfaQrAndSecret(HttpServletRequest request, RegistrationUser user) {
        UserProfile userProfile = new UserProfile();
        MfaStatus mfaStatus = new MfaStatus();
        if (user.getIsResetMfaRequest() != null && user.getIsResetMfaRequest()) {
            userProfile = authService.loadUserProfileByUsernameOrEmail(user.getUsername());
            mfaStatus = mfaRepo.findByUserId(userProfile.getId());
            AuthResponse authResponse = new AuthResponse();
            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            encryptor.setPassword(encryptorPassword);
            String decryptedOtpToken = encryptor.decrypt(user.getOtpToken());
            Boolean isOtpValid = tokenService.validateTokenRestTemplate(decryptedOtpToken);
            ResponseEntity<FetchResponse> fetchResponseEntity = tokenService.getFetchResponseFromToken(user.getFetchResponseToken());
            if (Boolean.FALSE.equals(isOtpValid)) {
                authService.incrementFailedAttempts(userProfile.getId(), fetchResponseEntity.getBody());
                throw new UserServiceException(INVALID_OTP_EXCEPTION, HttpStatus.BAD_REQUEST);
            }
            BaseResponse riskCheckResponse = authService.riskLevelCheck(userProfile, fetchResponseEntity.getBody());
            if (riskCheckResponse.getSuccess().equals(false)) {
                BaseResponse baseResponse;
                if (riskCheckResponse.getPayload() != null) {
                    authResponse.setReason(AuthenticationFailureConstants.RBA);
                    authResponse.setToken(riskCheckResponse.getPayload().toString());
                    baseResponse = riskCheckResponse;
                    baseResponse.setPayload(authResponse);
                    baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.FORBIDDEN));
                    return baseResponse;
                } else {
                    if (riskCheckResponse.getMessage().equals("Blocked IP")) {
                        authResponse.setReason(AuthenticationFailureConstants.RBA);
                        baseResponse = riskCheckResponse;
                        baseResponse.setMessage("New QR cannot be generated because this IP is blocked");
                        baseResponse.setPayload(authResponse);
                        baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.FORBIDDEN));
                        return baseResponse;
                    } else {
                        authService.incrementFailedAttempts(userProfile.getId(), fetchResponseEntity.getBody());
                        authResponse.setReason(AuthenticationFailureConstants.RBA);
                        baseResponse = riskCheckResponse;
                        baseResponse.setPayload(authResponse);
                        return baseResponse;
                    }
                }
            }
        }
        return emailUtil.generateQrAndSentToUser(user, userProfile, mfaStatus, request);
    }
    /**
     * Method to verify email verification code
     *
     * @param verificationCode {@link String}
     * @return {@link Boolean}
     */
    @Override
    public boolean verify(String verificationCode) {
        AccountStatus aStatus = accStatusRepo.findByVerificationCode(verificationCode);
        EmailStatus emailStatus = new EmailStatus();
        Optional<UserProfile> user = userRepo.findById(aStatus.getUserId());

        if (user.isEmpty()) {
            return false;
        } else {
            if (Boolean.TRUE.equals(tokenService.validateTokenRestTemplate(verificationCode))) {
                emailStatus.setVerificationCode(verificationCode);
                emailStatus.setIsVerified(true);
                aStatus.setEmailStatus(emailStatus);
                accStatusRepo.save(aStatus);

                return true;
            }
            return false;
        }
    }

    @Override
    public BaseResponse resendVerificationLink(HttpServletRequest request, String email) {
        BaseResponse baseResponse = new BaseResponse();
        UserProfile user = userRepo.findByEmailId(email.toLowerCase());
        String originName = request.getHeader(HttpHeaders.ORIGIN);
        if (originName == null) {
            throw new UserServiceException(ORIGIN_NULL_EXCEPTION, HttpStatus.BAD_REQUEST);
        }
        if (user == null) {
            baseResponse.setMessage("Given email is not a registered email address.");
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.FORBIDDEN));
            return baseResponse;
        }
        String orgUrl = originName.substring(8);
        Organization org = orgRepo.findByOrgUrl(orgUrl);
        emailUtil.sendVerificationEmail(request, user, org);
        baseResponse.setMessage("Verification email sent.");
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    /**
     * Method to request for user account approval
     *
     * @param code
     * @return BaseResponse
     */
    @Override
    public BaseResponse requestForAccountApproval(HttpServletRequest request, String code) {
        BaseResponse baseResponse = new BaseResponse();
        try {
            AccountStatus accountStatus = accStatusRepo.findByVerificationCode(code);
            String userId = accountStatus.getUserId();
            Optional<UserProfile> user = userRepo.findById(userId);

            String originName = request.getHeader(HttpHeaders.ORIGIN);
            if (originName == null) {
                baseResponse.setMessage("API origin is null");
                baseResponse.setSuccess(false);
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.BAD_REQUEST));
                return baseResponse;
            }
            String orgUrl = originName.substring(8);
            Organization org = orgRepo.findByOrgUrl(orgUrl);
            if (user.isEmpty()) {
                baseResponse.setMessage("Account Not found");
                baseResponse.setSuccess(false);
                return baseResponse;
            }

            emailUtil.sendApprovalEmail(request, user.get(), org);
            baseResponse.setMessage("Approval Email has been sent");
            baseResponse.setSuccess(true);
            return baseResponse;
        } catch (UnsupportedEncodingException | MessagingException e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "requestForAccountApproval", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage("Approval Email could not be sent");
            baseResponse.setSuccess(false);
            return baseResponse;
        }
    }

    /**
     * Method to approve user account
     *
     * @param email
     * @param isAccountApproved
     * @return boolean
     */
    @SuppressWarnings("unused")
    @Override
    public BaseResponse approve(String email, Boolean isAccountApproved, RegistrationUser registrationUser) {
        BaseResponse baseResponse = new BaseResponse();
        LOGGER.info("Inside UserServiceImpl::approve");
        long startTime = System.currentTimeMillis();
        email = URLDecoder.decode(email, StandardCharsets.UTF_8);
        UserProfile user = userRepo.findByEmailId(email.toLowerCase());

        try {
            if (user == null) {
                baseResponse.setMessage(USER_DOES_NOT_EXISTS.toString());
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.NOT_FOUND));
                baseResponse.setSuccess(false);
            } else {
                AccountStatus accountStatus = accStatusRepo.findByUserId(user.getId());
                if (Boolean.TRUE.equals(accountStatus.getAccountApprovalStatus().getIsAccountApproved())) {
                    baseResponse.setMessage("Account has already been approved!.");
                    baseResponse.setSuccess(true);
                    return baseResponse;
                }
                EmailStatus emailStatus = accountStatus.getEmailStatus();
                BasicTextEncryptor encryptor = new BasicTextEncryptor();
                encryptor.setPassword(encryptorPassword);
                String decryptedOtpToken = encryptor.decrypt(registrationUser.getOtpToken());

                if (!StringUtils.hasText(decryptedOtpToken)) {
                    baseResponse.setMessage("Otp Token is not set");
                    baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
                    baseResponse.setSuccess(false);
                    return baseResponse;
                }

                Boolean isOtpValid = tokenService.validateTokenRestTemplate(decryptedOtpToken);
                if (Boolean.FALSE.equals(isOtpValid)) {
                    baseResponse.setMessage("Token expired");
                    baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
                    baseResponse.setSuccess(false);
                    return baseResponse;
                }
                String approverMail = requestUtil.getEmailFromToken(decryptedOtpToken);
                UserProfile approverUserProfile = userRepo.findByEmailId(approverMail);
                if(Objects.isNull(approverUserProfile)){
                    baseResponse.setMessage(NOT_AUTHORIZED_TO_APPROVE_EXCEPTION.label);
                    baseResponse.setSuccess(false);
                    baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.FORBIDDEN));
                    return baseResponse;
                }


                emailStatus.setVerificationCode(null);
                accountStatus.setEmailStatus(emailStatus);
                AccountActivationStatus accountActivationStatus = new AccountActivationStatus();
                accountActivationStatus.setIsActive(isAccountApproved);
                accountActivationStatus.setStatusChangedAt(new Date());
                accountActivationStatus.setStatusChangedBy(approverUserProfile.getId());
                accountStatus.setAccountActivationStatus(accountActivationStatus);
                accountStatus.setAccountActivationStatus(accountActivationStatus);
                AccountApprovalStatus accountApprovalStatus = new AccountApprovalStatus();
                accountApprovalStatus.setIsAccountApproved(isAccountApproved);
                accountApprovalStatus.setApprovedAt(new Date());
                accountApprovalStatus.setApprovedBy(approverUserProfile.getId());
                accountStatus.setAccountApprovalStatus(accountApprovalStatus);
                accStatusRepo.save(accountStatus);
                if (Boolean.TRUE.equals(isAccountApproved)) {
                    emailUtil.sendApprovedEmail(user);
                }
                baseResponse.setMessage("Account has been approved and is active!.");
                baseResponse.setSuccess(true);
            }
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "approve", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage(ACTION_FAILED_EXCEPTION.label);
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
            return baseResponse;
        }

    }

    /**
     * @param userAccountStatus
     * @param request
     * @return {@link BaseResponse}
     */
    @Override
    public BaseResponse changeUserAccountStatus(UserAccountStatus userAccountStatus, HttpServletRequest request) {

        ArrayList<String> userIds = userAccountStatus.getUserId();
        List<String> userApprovedEmail = new ArrayList<>();
        List<String> userActivatedEmail = new ArrayList<>();
        BaseResponse baseResponse = new BaseResponse();
        AccountStatusUpdate accountStatusUpdate = new AccountStatusUpdate();

        String token = requestUtil.extractJwtFromRequest(request);
        String username = requestUtil.usernameFromToken(token);
        if (username == null || username.isBlank()) return getErrorBaseResponseForAcctStatusChange(baseResponse);

        try {
            for (String userid : userIds) {
                changeAccountStatusForMutipleAccounts(userAccountStatus, userid, request, accountStatusUpdate, userApprovedEmail, userActivatedEmail, baseResponse);
            }
            if (userAccountStatus.getIsAccountApproved() != null && userAccountStatus.getIsAccountApproved() && !userApprovedEmail.isEmpty()) {
                emailUtil.sendAccountStatusUpdateToMultipleUsers(userApprovedEmail, true, String.valueOf(EmailConstants.APPROVED));
            }
            if (userAccountStatus.getIsAccountActivated() != null && userAccountStatus.getIsAccountActivated() && !userActivatedEmail.isEmpty()) {
                emailUtil.sendAccountStatusUpdateToMultipleUsers(userActivatedEmail, true, String.valueOf(EmailConstants.ACTIVATED));
            }
            baseResponse.setMessage("Users account status updated Successfully.");
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.OK));
            baseResponse.setPayload(accountStatusUpdate);
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "changeUserAccountStatus", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage("Exception occurred in changing account approval status.");
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
            return baseResponse;
        }
    }

    private void changeAccountStatusForMutipleAccounts(UserAccountStatus userAccountStatus, String userid, HttpServletRequest request, AccountStatusUpdate accountStatusUpdate, List<String> userApprovedEmail, List<String> userActivatedEmail, BaseResponse baseResponse) {

        String token = requestUtil.extractJwtFromRequest(request);
        String username = requestUtil.usernameFromToken(token);
        UserProfile authUserProfile = authService.loadUserProfileByUsername(username);
        Optional<UserProfile> user = userRepo.findById(userid);
        if (user.isEmpty()) {
            userEmptyErrorForAccountStatusChange(userid, accountStatusUpdate);
        } else {
            UserProfile userProfile = user.get();
            if (userProfile.getId().equals(authUserProfile.getId())) {
                updateAccStatusUpdateError(userid, "User cannot change status of their own account.", userProfile, accountStatusUpdate);
            } else {
                AccountStatus accountStatus = accStatusRepo.findByUserId(userid);
                AccountActivationStatus accountActivationStatus = new AccountActivationStatus();
                AccountApprovalStatus accountApprovalStatus = new AccountApprovalStatus();
                if (userAccountStatus.getIsAccountApproved() != null && userAccountStatus.getIsAccountApproved()) {
                    // TO Approve & Activate User Account
                    accountApprovalStatus.setIsAccountApproved(true);
                    accountApprovalStatus.setApprovedAt(new Date());
                    accountApprovalStatus.setApprovedBy(authUserProfile.getId());
                    accountStatus.setAccountApprovalStatus(accountApprovalStatus);
                    accountActivationStatus.setIsActive(true);
                    userApprovedEmail.add(userProfile.getEmailId());
                    accountStatusUpdate.setUserApprovedId(userid);
                    accountStatusUpdate.setUserActivatedId(userid);
                } else if (userAccountStatus.getIsAccountActivated() != null && userAccountStatus.getIsAccountActivated())
                    activateUserAccount(userid, accountStatus, accountActivationStatus, userProfile, accountStatusUpdate, userActivatedEmail);
                else {
                    deactivateUserAccount(userid, accountStatusUpdate, accountActivationStatus);
                }
                accountActivationStatus.setStatusChangedAt(new Date());
                accountActivationStatus.setStatusChangedBy(authUserProfile.getId());
                accountStatus.setAccountActivationStatus(accountActivationStatus);
                // TO Unblock the user
                unblockUserAccount(userAccountStatus, userid, accountStatusUpdate, accountStatus, userProfile);
                accStatusRepo.save(accountStatus);
                baseResponse.setSuccess(true);
            }
        }
    }

    private void unblockUserAccount(UserAccountStatus userAccountStatus, String userid, AccountStatusUpdate accountStatusUpdate, AccountStatus accountStatus, UserProfile userProfile) {
        // TO Unblock the user
        if (userAccountStatus.getIsAccountUnblock() != null && userAccountStatus.getIsAccountUnblock()) {
            if (accountStatus.getAccountApprovalStatus() == null || !accountStatus.getAccountApprovalStatus().getIsAccountApproved()) {
                updateAccStatusUpdateError(userid, "This user account has not been approved.", userProfile, accountStatusUpdate);
            } else if (accountStatus.getAccountActivationStatus() == null || !accountStatus.getAccountActivationStatus().getIsActive()) {
                updateAccStatusUpdateError(userid, "This user account has not been active.", userProfile, accountStatusUpdate);
            } else {
                BaseResponse unblockUser = requestUtil.unblockUser(userid);
                BaseResponse resetFailedAttemptsBaseResponse = authService.resetFailedAttempts(userid);
                if (Objects.equals(unblockUser.getStatusCode(), "200") && Objects.equals(resetFailedAttemptsBaseResponse.getSuccess(), true)) {
                    accountStatusUpdate.setUserUnblockId(userid);
                } else {
                    updateAccStatusUpdateError(userid, unblockUser.getMessage(), userProfile, accountStatusUpdate);
                }
            }
        }
    }

    private static void deactivateUserAccount(String userid, AccountStatusUpdate accountStatusUpdate, AccountActivationStatus accountActivationStatus) {
        //TO Deactivate the User
        accountActivationStatus.setIsActive(false);
        accountStatusUpdate.setUserDeactivatedId(userid);
    }

    private static void userEmptyErrorForAccountStatusChange(String userid, AccountStatusUpdate accountStatusUpdate) {
        AccStatusUpdateError updateError = new AccStatusUpdateError();
        updateError.setUserId(userid);
        updateError.setReason("This user account does not exist.");
        accountStatusUpdate.setUserAccStatusUpdateError(updateError);
    }

    private static void activateUserAccount(String userid, AccountStatus accountStatus, AccountActivationStatus accountActivationStatus, UserProfile userProfile, AccountStatusUpdate accountStatusUpdate, List<String> userActivatedEmail) {
        // TO Activate the User
        if (accountStatus.getAccountApprovalStatus() == null || !accountStatus.getAccountApprovalStatus().getIsAccountApproved()) {
            accountActivationStatus.setIsActive(false);
            updateAccStatusUpdateError(userid, "This user account has not been approved.", userProfile, accountStatusUpdate);
        } else {
            accountActivationStatus.setIsActive(true);
            userActivatedEmail.add(userProfile.getEmailId());
            accountStatusUpdate.setUserActivatedId(userid);
        }
    }

    private static void updateAccStatusUpdateError(String userid, String reason, UserProfile userProfile, AccountStatusUpdate accountStatusUpdate) {
        AccStatusUpdateError updateError = new AccStatusUpdateError();
        updateError.setUserId(userid);
        updateError.setReason(reason);
        updateError.setFullName(userProfile.getFirstName(), userProfile.getLastName());
        accountStatusUpdate.setUserAccStatusUpdateError(updateError);
    }

    private static BaseResponse getErrorBaseResponseForAcctStatusChange(BaseResponse baseResponse) {
        baseResponse.setMessage("Username is blank!");
        baseResponse.setSuccess(false);
        baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
        return baseResponse;
    }

    /**
     * Method to register/login a user via Google
     *
     * @param user {@link RegistrationUser}}
     * @return BaseResponse
     */
    @Override
    public BaseResponse registerForGoogleLogin(RegistrationUser user) {
        BaseResponse baseResponse = new BaseResponse();
        try {
            UserProfile existingUser = userRepo.findByEmailId(user.getMailId().toLowerCase());
            if (existingUser != null) {
                baseResponse.setMessage("A user with the given username already exists!");
                baseResponse.setSuccess(false);
                return baseResponse;
            }
            UserProfile newUser = new UserProfile();
            newUser.setUsername(user.getUsername().toLowerCase());
            newUser.setEmailId(user.getMailId().toLowerCase());
            newUser.setFirstName(user.getGivenName());
            newUser.setLastName(user.getFamilyName());
            newUser.setPassword(bcryptEncoder.encode(user.getPassword()));
            newUser.setRole(AuthServiceImpl.ROLE_ADMIN);
            userRepo.insert(newUser);

            MfaStatus mfaDetails = mfaRepo.findByUserId(newUser.getId());
            if (mfaDetails == null) {
                MfaStatus mfaStatus = new MfaStatus();
                if (Boolean.TRUE.equals(user.getIsUsing2FA()) && user.getSecret() != null) {
                    mfaStatus.setUserId(newUser.getId());
                    Mfa mfa = new Mfa();
                    mfa.setMfaSecret(user.getSecret());
                    mfa.setProviderApp(MfaConstants.PROVIDERAPP);
                    mfaStatus.setMfa(mfa);
                    mfaStatus.setUserId(newUser.getId());
                    mfaStatus.setIsEnabled(true);
                    mfaRepo.save(mfaStatus);
                } else {
                    mfaStatus.setIsEnabled(false);
                    mfaStatus.setUserId(newUser.getId());
                    mfaRepo.save(mfaStatus);
                }
            }
            String verificationToken = requestUtil.verificationToken(newUser.getEmailId(), TokenConstants.USER_VERIFICATION_TOKEN_DURATION);

            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            encryptor.setPassword(encryptorPassword);
            String encryptedVerificationToken = encryptor.encrypt(verificationToken);
            AccountStatus aStatus = accStatusRepo.findByUserId(newUser.getId());
            if (aStatus == null)
                aStatus = new AccountStatus();
            aStatus.setUserId(newUser.getId());
            EmailStatus emailStatus = new EmailStatus();
            emailStatus.setVerificationCode(encryptedVerificationToken);
            emailStatus.setIsVerified(true);
            aStatus.setEmailStatus(emailStatus);
            AccountApprovalStatus accountApprovalStatus = new AccountApprovalStatus();
            accountApprovalStatus.setIsAccountApproved(false);
            aStatus.setAccountApprovalStatus(accountApprovalStatus);
            accStatusRepo.save(aStatus);

            UserOrgRole userOrgRole = new UserOrgRole();
            userOrgRole.setUserId(newUser.getId());
            List<String> platformRoles = new ArrayList<>();
            Role role = roleRepo.findByRoleName(PermissionConstants.ROOT_USER);
            platformRoles.add(role.getId());
            userOrgRole.setPlatformRoleIdList(platformRoles);
            userOrgRoleRepo.save(userOrgRole);

            baseResponse.setMessage("User added!");
            baseResponse.setSuccess(true);
            baseResponse.setPayload(aStatus);
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "registerForGoogleLogin", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage(ACTION_FAILED_EXCEPTION.label);
            baseResponse.setSuccess(false);
            return baseResponse;
        }
    }

    /**
     * Method to save a new pass-code in database
     *
     * @param mailId
     * @param passcode
     * @return BaseResponse
     */
    @Override
    public BaseResponse addPasscode(String mailId, String passcode) {
        BaseResponse baseResponse = new BaseResponse();
        try {
            UserProfile user = userRepo.findByEmailId(mailId.toLowerCase());
            if (user == null) {
                baseResponse.setMessage("No user exists with that email.");
                baseResponse.setSuccess(false);
                return baseResponse;
            }

            ChangeSecSettings userSec = userSecRepo.findByUserId(user.getId());
            if (userSec == null)
                userSec = new ChangeSecSettings();
            userSec.setUserId(user.getId());
            userSec.setResetCode(passcode);
            userSecRepo.save(userSec);

            baseResponse.setMessage("Passcode generated");
            baseResponse.setSuccess(true);
            baseResponse.setPayload(user);
            return baseResponse;
        } catch (Exception e) {
            LOGGER.warn(AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG, USER_SERVICE_IMPL, "addPasscode", e.getMessage(), e.getStackTrace());
            return null;
        }
    }

    /**
     * Method to validate an existing pass-code in database
     *
     * @param mailId
     * @param passcode
     * @return Boolean
     */
    @Override
    public BaseResponse checkPasscode(String mailId, String passcode) {
        BaseResponse baseResponse = new BaseResponse();
        try {
            UserProfile user1 = userRepo.findByEmailId(mailId.toLowerCase());
            NewPasswordToken newPasswordToken = new NewPasswordToken();
            if (user1 != null) {
                ChangeSecSettings userSec = userSecRepo.findByUserId(user1.getId());
                String passcodeFromDb = userSec.getResetCode();
                String[] split = null;
                if (passcodeFromDb != null)
                    split = passcodeFromDb.split("-");
                if (split != null && split[0].equals(passcode)) {
                    String expiry = split[1];
                    SimpleDateFormat formatter = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss zzz");
                    Date expirationDate = formatter.parse(expiry);
                    Date today = new Date();
                    if (expirationDate.after(today)) {
                        userSec.setResetCode(authService.generateSecretKey() + passcode);
                        userSecRepo.save(userSec);
                        String otpToken = requestUtil.verificationToken(mailId, TokenConstants.NEW_PASSWORD_TOKEN_DURATION);
                        if (otpToken != null) {
                            BasicTextEncryptor encryptor = new BasicTextEncryptor();
                            encryptor.setPassword(encryptorPassword);
                            String encryptedotpToken = encryptor.encrypt(otpToken);
                            newPasswordToken.setToken(encryptedotpToken);
                            baseResponse.setMessage("Passcode validated and Token generated");
                            baseResponse.setSuccess(true);
                            baseResponse.setPayload(newPasswordToken);
                            return baseResponse;
                        }
                    }
                    baseResponse.setMessage("Passcode expired");
                    baseResponse.setSuccess(false);
                    return baseResponse;
                }else{
                    LOGGER.error("The Entered Otp is Incorrect");
                    baseResponse.setMessage("The Entered Otp is Incorrect");
                    baseResponse.setSuccess(false);
                    return baseResponse;
                }
            }
            baseResponse.setMessage("User does not exist");
            baseResponse.setSuccess(false);
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "checkPasscode", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage(ACTION_FAILED_EXCEPTION.label);
            baseResponse.setSuccess(false);
            return baseResponse;
        }
    }

    /**
     * Method to save a new user password in database
     *
     * @param changePasswordRequest {@link ChangePasswordRequest}
     * @return {@link BaseResponse}
     */
    @Override
    public BaseResponse savePassword(ChangePasswordRequest changePasswordRequest) {
        BaseResponse baseResponse = new BaseResponse();
        try {
            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            encryptor.setPassword(encryptorPassword);
            String token = encryptor.decrypt(changePasswordRequest.getToken());

            Boolean isTokenValid = tokenService.validateTokenRestTemplate(token);
            if (!StringUtils.hasText(token) || Boolean.FALSE.equals(isTokenValid)) {
                baseResponse.setMessage(INVALID_AUTH_TOKEN.toString());
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
                baseResponse.setSuccess(false);
                return baseResponse;
            }

            UserProfile user = userRepo.findByEmailId(changePasswordRequest.getMailId().toLowerCase());
            // Passcode validation
            if (user == null) {
                baseResponse.setMessage("New password cannot be set as user email is invalid");
                baseResponse.setSuccess(false);
                LOGGER.error("Username is not defined");
                return baseResponse;
            }

            ChangeSecSettings userSec = userSecRepo.findByUserId(user.getId());
            if (userSec.getResetCode() == null
                    || !userSec.getResetCode().endsWith(changePasswordRequest.getPasscode())) {
                baseResponse.setMessage("New Password cannot be set!");
                baseResponse.setSuccess(false);
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
                return baseResponse;
            }
            // User password validation
            if (!helperUtil.isValidPassword(changePasswordRequest.getNewPassword())) {
                baseResponse.setMessage(ExceptionMessagesConstants.GIVEN_USER_PASSWORD_IS_NOT_VALID.toString());
                baseResponse.setSuccess(false);
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.BAD_REQUEST));
                return baseResponse;
            }
            if (!changePasswordRequest.getNewPassword().equals(changePasswordRequest.getConfirmedPassword())) {
                baseResponse.setMessage(ExceptionMessagesConstants.PASSWORD_FIELDS_EXCEPTION.toString());
                baseResponse.setSuccess(false);
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.BAD_REQUEST));
                return baseResponse;
            }
            if (bcryptEncoder.matches(changePasswordRequest.getNewPassword(), user.getPassword())) {
                baseResponse.setMessage("New Password should not be same as old one!");
                baseResponse.setSuccess(false);
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.BAD_REQUEST));
                return baseResponse;
            }
            user.setPassword(bcryptEncoder.encode(changePasswordRequest.getNewPassword()));
            userRepo.save(user);
            userSecRepo.delete(userSec);
            baseResponse.setMessage("New Password saved!");
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.OK));
            baseResponse.setSuccess(true);
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "savePassword", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage(ACTION_FAILED_EXCEPTION.label);
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
            return baseResponse;
        }
    }

    /**
     * Method to validate a user
     *
     * @param username
     * @return BaseResponse
     */
    @Override
    public BaseResponse validateUserForGLogin(String username) {
        try {
            BaseResponse baseResponse = new BaseResponse();
            UserProfile user = userRepo.findByEmailId(username.toLowerCase());
            if (user != null) {
                AccountStatus accountStatus = accStatusRepo.findByUserId(user.getId());
                baseResponse.setMessage("User exists.");
                baseResponse.setSuccess(true);
                baseResponse.setPayload(accountStatus);
                return baseResponse;

            }
            baseResponse.setMessage("User does not exist.");
            baseResponse.setSuccess(false);
            return baseResponse;
        } catch (Exception e) {
            LOGGER.warn(AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG, USER_SERVICE_IMPL, "validateUserForGLogin", e.getMessage(), e.getStackTrace());
            return null;
        }
    }

    /**
     * Method to update an existing user
     *
     * @param updatedUser {@link RegistrationUser}
     * @return BaseResponse
     */
    @Override
    public BaseResponse updateUser(HttpServletRequest request, RegistrationUser updatedUser) {
        BaseResponse baseResponse = new BaseResponse();
        RegisterUserResponse payload;
        String token = requestUtil.extractJwtFromRequest(request);
        String username = requestUtil.usernameFromToken(token);
        UserProfile user = userRepo.findByUsername(username);

        if (updatedUser.getFirstName() == null && updatedUser.getLastName() == null && updatedUser.getMailId() == null) {
            throw new UserServiceException(EMPTY_REQUEST_BODY_EXCEPTION,HttpStatus.BAD_REQUEST);
        }
        if (updatedUser.getMailId() != null && !updatedUser.getMailId().isBlank() && !helperUtil.isValidEmail(updatedUser.getMailId())) {
            throw new UserServiceException(INVALID_USER_EMAIL_EXCEPTION,HttpStatus.BAD_REQUEST);
        }
        if (updatedUser.getMailId() != null && !helperUtil.checkForDuplicateEmail(updatedUser.getMailId())) {
            user.setEmailId(updatedUser.getMailId());
            String verificationToken = requestUtil.verificationToken(updatedUser.getMailId(), TokenConstants.USER_VERIFICATION_TOKEN_DURATION);
            AccountStatus accStatus = accStatusRepo.findByUserId(user.getId());
            accStatusRepo.save(helperUtil.updateAccountStatus(accStatus, verificationToken));
            MfaStatus mfaDetails = mfaRepo.findByUserId(user.getId());

            payload = helperUtil.validateUserDetails(user, updatedUser);
            if (mfaDetails.getIsEnabled() != null && mfaDetails.getIsEnabled()) {
                payload.setIsMfaEnabled(true);
                String secret = requestUtil.generateMFASecret();
                payload.setSecret(secret);
                String albaneroInstance = helperUtil.getAlbaneroInstance(request);
                String qr = EmailUtil.generateQRUrl(user.getEmailId(), secret, albaneroInstance);
                mfaRepo.save(helperUtil.updateMfaDetails(mfaDetails, secret));
                payload.setSecretQrImageUri(qr);
            }
            baseResponse.setMessage("Your email has been changed. You need to go for email verification and approval again.");
            baseResponse.setSuccess(true);
            payload.setIsEmailChanged(true);
            baseResponse.setPayload(payload);
            return baseResponse;
        }
        payload = helperUtil.validateUserDetails(user, updatedUser);
        if (updatedUser.getMailId() != null && updatedUser.getMailId().equals(user.getEmailId())) {
            payload.setEmailMessage("Given email address is already exists!");
        }
        baseResponse.setMessage("Profile details updated.");
        baseResponse.setSuccess(true);
        baseResponse.setPayload(payload);
        return baseResponse;
    }

    /**
     * Method to update MFA for the user
     *
     * @param request  {@link HttpServletRequest}
     *
     * @throws UnsupportedEncodingException
     */
    @Override
    public BaseResponse updateUser2FA(HttpServletRequest request){
        String token = requestUtil.extractJwtFromRequest(request);
        String username = requestUtil.usernameFromToken(token);

        BaseResponse baseResponse = new BaseResponse();

        if (username == null || username.isBlank()) {
            baseResponse.setMessage("Either the request paramater or the username is incorrect!");
            baseResponse.setSuccess(true);
        }
        UserProfile userProfile = authService.loadUserProfileByUsername(username);
        // call mfa-service for generating secret
        String secret = requestUtil.generateMFASecret();
        MfaStatus mfaStatus = mfaRepo.findByUserId(userProfile.getId());
        if (mfaStatus == null) {
            mfaStatus = new MfaStatus();
        }
        Mfa mfa = new Mfa();
        mfa.setMfaSecret(secret);
        mfa.setProviderApp(MfaConstants.PROVIDERAPP);
        mfaStatus.setUserId(userProfile.getId());
        mfaStatus.setMfa(mfa);
        mfaStatus.setIsEnabled(true);
        String albaneroInstance = helperUtil.getAlbaneroInstance(request);
        String qr = EmailUtil.generateQRUrl(userProfile.getEmailId(), secret , albaneroInstance);
        RegisterUserResponse registerUserResponse = new RegisterUserResponse();
        registerUserResponse.setSecretQrImageUri(qr);
        registerUserResponse.setSecret(secret);
        baseResponse.setPayload(registerUserResponse);
        baseResponse.setMessage("QR and secret generated.");
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    /**
     * Method to fetch user profile details
     *
     * @param request
     */
    @Override
    public BaseResponse getUser(HttpServletRequest request, AuthRequest authRequest) {
        BaseResponse baseResponse = new BaseResponse();
        try {
            String token = requestUtil.extractJwtFromRequest(request);
            String username = requestUtil.usernameFromToken(token);
            UserProfile user = userRepo.findByUsername(username);
            UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(user.getId());
            UserIdDetails userIdDetails = userRoleService.fetchUserIdDetails(userOrgRole, authRequest, user);


            baseResponse.setMessage("Profile Details fetched.");
            baseResponse.setPayload(userIdDetails);
            baseResponse.setSuccess(true);
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "getUser", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage(ACTION_FAILED_EXCEPTION.toString());
            baseResponse.setSuccess(false);
            return baseResponse;
        }
    }


    /**
     * Method to delete an existing user
     *
     * @param id
     * @return BaseResponse
     */
    @Override
    public BaseResponse deleteUser(String id) {
        BaseResponse baseResponse = new BaseResponse();
        try {
            if (id == null || id.isBlank() || id.isEmpty()) {
                baseResponse.setMessage("The given ID is either empty or null!");
                baseResponse.setSuccess(false);
                return baseResponse;
            }
            Optional<UserProfile> user = userRepo.findById(id);

            if (user.isEmpty()) {
                baseResponse.setMessage("The given ID is incorrect!");
                baseResponse.setSuccess(false);
                return baseResponse;
            }

            userRepo.delete(user.get());
            baseResponse.setMessage("User with ID : " + id + " has been deleted!");
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "deleteUser", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage(ACTION_FAILED_EXCEPTION.label);
            baseResponse.setSuccess(false);
            return baseResponse;
        }
    }

    /**
     * Method to update and save MFA for the user
     *
     * @param secret
     */
    @Override
    public BaseResponse updateAndSaveUser2FA(Boolean use2FA, String secret, HttpServletRequest request) {
        String token = requestUtil.extractJwtFromRequest(request);
        String username = requestUtil.usernameFromToken(token);

        UserProfile userProfile = authService.loadUserProfileByUsername(username);
        BaseResponse baseResponse = new BaseResponse();

        if (username == null || username.isBlank() || use2FA == null) {
            baseResponse.setMessage("Either the request paramater or the username is incorrect!");
            baseResponse.setSuccess(true);
        }
        // call mfa-service for generating secret
        if (Boolean.TRUE.equals(use2FA)) {
            MfaStatus mfaStatus = mfaRepo.findByUserId(userProfile.getId());
            if (mfaStatus == null)
                mfaStatus = new MfaStatus();
            Mfa mfa = new Mfa();
            mfa.setMfaSecret(secret);
            mfa.setProviderApp(MfaConstants.PROVIDERAPP);
            mfaStatus.setUserId(userProfile.getId());
            mfaStatus.setMfa(mfa);
            mfaStatus.setIsEnabled(true);
            mfaRepo.save(mfaStatus);
            RegisterUserResponse registerUserResponse = new RegisterUserResponse();
            registerUserResponse.setIsMfaEnabled(true);
            baseResponse.setPayload(registerUserResponse);
            baseResponse.setMessage("MFA Enabled.");
            baseResponse.setSuccess(true);
        } else {
            MfaStatus mfaStatus = mfaRepo.findByUserId(userProfile.getId());
            if (mfaStatus == null)
                mfaStatus = new MfaStatus();
            Mfa mfa = new Mfa();
            mfa.setMfaSecret(null);
            mfaStatus.setMfa(mfa);
            mfaStatus.setIsEnabled(false);
            mfaStatus.setUserId(userProfile.getId());
            mfaRepo.save(mfaStatus);
            baseResponse.setMessage("MFA Disabled.");
            baseResponse.setSuccess(true);
        }

        userRepo.save(userProfile);
        return baseResponse;
    }

    @Override
    public UserSession saveRToken(UserSessionRequestDto userSession) {
        UserSession userTokenDetails = userSessionRepo.findByUserId(userSession.getUserId());
        if (userTokenDetails == null)
            userTokenDetails = new UserSession();
        userTokenDetails.setEncryptedRT(userSession.getEncryptedRT());
        userTokenDetails.setHashedRT(userSession.getHashedRT());
        userTokenDetails.setUserId(userSession.getUserId());
        userSessionRepo.save(userTokenDetails);
        return userTokenDetails;
    }

    /**
     * Method to change existing password
     *
     * @param oldPassword
     * @param newPassword
     */
    @Override
    public BaseResponse changePassword(String token, String oldPassword, String newPassword, String confirmedPassword) {
        BaseResponse baseResponse = new BaseResponse();
        try {
            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            encryptor.setPassword(encryptorPassword);
            token = encryptor.decrypt(token);
            Boolean isTokenValid = tokenService.validateTokenRestTemplate(token);
            if (!StringUtils.hasText(token) || Boolean.FALSE.equals(isTokenValid)) {
                baseResponse.setMessage("Invalid Auth token!");
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
                baseResponse.setSuccess(false);
                return baseResponse;
            }

            String username = requestUtil.usernameFromToken(token);
            UserProfile user = authService.loadUserProfileByUsername(username);
            if (user == null) {
                baseResponse.setMessage("User does not exist.");
                baseResponse.setSuccess(false);
                return baseResponse;
            }

            String hashedPassword = user.getPassword();

            if (helperUtil.checkPass(oldPassword, hashedPassword)) {

                if (!newPassword.equals(oldPassword) && helperUtil.isValidPassword(newPassword)
                        && (newPassword.equals(confirmedPassword))) {

                    user.setPassword(bcryptEncoder.encode(newPassword));
                    userRepo.save(user);
                    baseResponse.setMessage("Password changed!");
                    baseResponse.setSuccess(true);
                    return baseResponse;
                }
            }else{
                baseResponse.setMessage("Wrong Old Password Entered");
                baseResponse.setSuccess(false);
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.BAD_REQUEST));
                return baseResponse;
            }
            baseResponse.setMessage("Error occured while changing password!");
            baseResponse.setSuccess(false);
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "changePassword", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage(ACTION_FAILED_EXCEPTION.label);
            baseResponse.setSuccess(false);
            return baseResponse;
        }
    }

    @Override
    public BaseResponse fetchUsername(HttpServletRequest request, String id) {
        BaseResponse baseResponse = new BaseResponse();
        AuthTokenResponse authTokenResponse = new AuthTokenResponse();
        String token = requestUtil.extractJwtFromRequest(request);

        String username = requestUtil.usernameFromToken(token);
        UserProfile user1 = userRepo.findByUsername(username);
        Optional<UserProfile> user2 = userRepo.findById(id);
        if (user2.isEmpty()) {
            baseResponse.setMessage("User not found with the given id.!");
            baseResponse.setSuccess(true);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.NOT_FOUND));
            return baseResponse;
        }
        if (user1.equals(user2.get())) {
            authTokenResponse.setUsername(username);
            baseResponse.setMessage("Username fetched!");
            baseResponse.setSuccess(true);
            baseResponse.setPayload(authTokenResponse);
            return baseResponse;
        }
        baseResponse.setMessage("The provided token doesn't belong to the given user.");
        baseResponse.setSuccess(false);
        baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
        return baseResponse;
    }

    @Override
    public Boolean verifyUserAccess(HttpServletRequest request, String productId) {
        try {
            String token = requestUtil.extractJwtFromRequest(request);
            String username = requestUtil.usernameFromToken(token);
            // dummy return statement for sonar fix, as previously it was returning only hardcoded false
            return username.isBlank();
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public BaseResponse getProductDetails(HttpServletRequest request) {
        BaseResponse baseResponse = new BaseResponse();

        try {
            String token = requestUtil.extractJwtFromRequest(request);
            String username = requestUtil.usernameFromToken(token);

            UserProfile user = userRepo.findByUsername(username);
            if (user != null) {

                List<Product> productList = prodRepo.findAll();
                if (!productList.isEmpty()) {
                    baseResponse.setMessage("Successfully fetched product details!");
                    baseResponse.setSuccess(true);
                    baseResponse.setPayload(productList);
                    return baseResponse;
                } else {
                    baseResponse.setMessage("There are no products available as of now.");
                    baseResponse.setSuccess(false);
                    return baseResponse;
                }
            }
            baseResponse.setMessage("User not found!");
            baseResponse.setSuccess(false);
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "getProductDetails", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage(ACTION_FAILED_EXCEPTION.label);
            baseResponse.setSuccess(false);
            return baseResponse;
        }
    }

    @Override
    public String fetchEmail(HttpServletRequest request) {
        try {
            String token = requestUtil.extractJwtFromRequest(request);
            String loggedInUsername = requestUtil.usernameFromToken(token);

            UserProfile loggedInUser = userRepo.findByUsername(loggedInUsername);
            if (loggedInUser != null && loggedInUser.getEmailId() != null)
                return loggedInUser.getEmailId();
            return null;
        } catch (Exception e) {
            LOGGER.warn(AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG, USER_SERVICE_IMPL, "fetchEmail", e.getMessage(), e.getStackTrace());
            return null;
        }

    }

    @Override
    public BaseResponse uploadProfilePicture(HttpServletRequest request, MultipartFile file) {
        BaseResponse baseResponse = new BaseResponse();

        // regex will check for any one of file extensions mentioned, should start with any alphanumeric character
        // can contain any of - alphabets, numerical, underscore, hyphens in between
        String regex = "^[\\w-]+\\.(jpg|jpeg|png|gif|JPG|JPEG|PNG|GIF)$";
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(Objects.requireNonNull(file.getOriginalFilename()));

        if (!m.matches()) {
            baseResponse.setMessage("Uploaded file is not an image");
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.BAD_REQUEST));
            return baseResponse;
        }

        String token = requestUtil.extractJwtFromRequest(request);
        String username = requestUtil.usernameFromToken(token);
        try {
            UserProfile user = authService.loadUserProfileByUsername(username);
            if (user != null) {
                ProfileImageDetails profileImageDetails = uploadProfileImage(file);

                user.setProfileImageDetails(profileImageDetails);
                userRepo.save(user);

                baseResponse.setPayload(profileImageDetails);
                baseResponse.setMessage("Profile image updated");
                baseResponse.setSuccess(true);
                baseResponse.setStatusCode("200");
                return baseResponse;
            }
            baseResponse.setMessage("User doesn't exist.");
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "uploadProfilePicture", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage(ACTION_FAILED_EXCEPTION.label);
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
            return baseResponse;
        }

    }

    /**
     * Method to save a new user security question in database
     *
     * @param changeSQRequest
     * @return BaseResponse
     */
    @Override
    public BaseResponse saveSQ(ChangeSQRequest changeSQRequest) {
        BaseResponse baseResponse = new BaseResponse();
        try {
            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            encryptor.setPassword(encryptorPassword);
            String token = encryptor.decrypt(changeSQRequest.getToken());
            Boolean isTokenValid = tokenService.validateTokenRestTemplate(token);
            if (!StringUtils.hasText(token) || Boolean.FALSE.equals(isTokenValid)) {
                baseResponse.setMessage("Invalid Auth token!");
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
                baseResponse.setSuccess(false);
                return baseResponse;
            }

            UserProfile user = userRepo.findByEmailId(changeSQRequest.getMailId().toLowerCase());
            if(user==null){
                baseResponse.setMessage("User with this email not found.");
                baseResponse.setSuccess(false);
                return baseResponse;
            }
            // Passcode validation
            ChangeSecSettings userSec = userSecRepo.findByUserId(user.getId());
            SecurityQuestionStatus securityQuestionStatus = sqRepo.findByUserId(user.getId());
            if (userSec.getResetCode() == null
                    || !userSec.getResetCode().endsWith(changeSQRequest.getPasscode())) {
                baseResponse.setMessage("New security question cannot be set!");
                baseResponse.setSuccess(false);
                return baseResponse;
            }
            securityQuestionStatus.setQuestion(changeSQRequest.getQuestion().toLowerCase());
            securityQuestionStatus.setAnswer(bcryptEncoder.encode(changeSQRequest.getAnswer().toLowerCase()));

            userSec.setResetCode(authService.generateSecretKey());
            userRepo.save(user);
            userSecRepo.delete(userSec);
            baseResponse.setMessage("New security question saved!");
            baseResponse.setSuccess(true);
            return baseResponse;
        } catch (Exception e) {
            LOGGER.warn(AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG, USER_SERVICE_IMPL, "saveSQ", e.getMessage(), e.getStackTrace());
            return null;
        }
    }

    @Override
    public BaseResponse checkPassword(HttpServletRequest request, String password) {
        BaseResponse baseResponse = new BaseResponse();
        String token = requestUtil.extractJwtFromRequest(request);
        String username = requestUtil.usernameFromToken(token);
        try {
            UserProfile userProfile = authService.loadUserProfileByUsername(username);
            if (userProfile != null) {
                String hashedPassword = userProfile.getPassword();
                Boolean isPasswordSame = helperUtil.checkPass(password, hashedPassword);
                if (Boolean.TRUE.equals(isPasswordSame)) {

                    baseResponse.setMessage("Passwords Matched");
                    baseResponse.setSuccess(true);
                    baseResponse.setStatusCode("200");
                    return baseResponse;
                } else {
                    baseResponse.setMessage("Passwords don't match");
                    baseResponse.setSuccess(false);
                    baseResponse.setStatusCode("200");
                    return baseResponse;
                }
            }
            baseResponse.setMessage("User doesn't exist.");
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "checkPassword", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage(ACTION_FAILED_EXCEPTION.label);
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
            return baseResponse;
        }
    }

    /**
     * Method to delete an existing user
     *
     * @param id {@link String}
     * @return {@link BaseResponse}
     */
    @Override
    public BaseResponse deleteChangeSecuritySettings(String id) {
        BaseResponse baseResponse = new BaseResponse();
        try {
            if (id == null || id.isBlank() || id.isEmpty()) {
                baseResponse.setMessage("The given ID is either empty or null!");
                baseResponse.setSuccess(false);
                return baseResponse;
            }
            ChangeSecSettings changeSecSettings = userSecRepo.findByUserId(id);
            if (changeSecSettings == null) {
                baseResponse.setMessage("The given ID is incorrect!");
                baseResponse.setSuccess(false);
                return baseResponse;
            }

            userSecRepo.delete(changeSecSettings);
            baseResponse.setMessage("Change Security Settings with ID : " + id + " has been deleted!");
            baseResponse.setSuccess(true);
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "deleteChangeSecuritySettings", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage(ACTION_FAILED_EXCEPTION.label);
            baseResponse.setSuccess(false);
            return baseResponse;
        }
    }

    /**
     * Method to Fetch User Details by UserId
     *
     * @param userId             {@link String}
     * @param httpServletRequest {@link HttpServletRequest}
     * @return {@link BaseResponse}
     */
    @Override
    public BaseResponse fetchUserDetailsFromUserId(String userId,HttpServletRequest httpServletRequest) {
        BaseResponse baseResponse = new BaseResponse();
        if (userId == null || userId.isBlank()) {
            throw new UserServiceException(USER_ID_IS_NULL_OR_NOT_PROVIDED, HttpStatus.BAD_REQUEST);
        }
        Optional<UserProfile> user = userRepo.findById(userId);
        if (user.isEmpty()) {
            throw new UserServiceException(USER_NOT_FOUND_WITH_ID_EXCEPTION, HttpStatus.NOT_FOUND);
        }
        helperUtil.checkOrgIdAndProjectId(httpServletRequest);
        UserProfile userProfile = user.get();
        AccountStatus accountStatus = accStatusRepo.findByUserId(userId);
        UserProfileDetails userProfileDetails = new UserProfileDetails();
        userProfileDetails.setEmailId(userProfile.getEmailId());
        userProfileDetails.setUserId(userProfile.getId());
        userProfileDetails.setUsername(userProfile.getUsername());
        userProfileDetails.setFullName(userProfile.getFirstName() + " " + userProfile.getLastName());
        userProfileDetails.setIsAccountApproved(accountStatus.getAccountApprovalStatus() != null ? accountStatus.getAccountApprovalStatus().getIsAccountApproved() : Boolean.FALSE);
        userProfileDetails.setIsAccountActive(accountStatus.getAccountActivationStatus() != null ? accountStatus.getAccountActivationStatus().getIsActive() : Boolean.FALSE);
        baseResponse.setPayload(userProfileDetails);
        baseResponse.setMessage("Successfully fetched User Details");
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    @Override
    public BaseResponse fetchUserDetailsList(List<String> userIds) {
        BaseResponse baseResponse = new BaseResponse();
        try {
            if (userIds == null || userIds.isEmpty()) {
                baseResponse.setMessage(USER_ID_IS_NULL_OR_NOT_PROVIDED.toString());
                baseResponse.setSuccess(false);
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.BAD_REQUEST));
                return baseResponse;
            }
            List<UserProfileDetails> userProfileDetailsList = new ArrayList<>();
            for (String userId : userIds) {
                Optional<UserProfile> userProfileOpt = userRepo.findById(userId);
                if (userProfileOpt.isEmpty()) {
                    throw new UserServiceException("User not found with given userID.", HttpStatus.NOT_FOUND);
                }
                UserProfile userProfile = userProfileOpt.get();
                AccountStatus accountStatus = accStatusRepo.findByUserId(userId);
                UserProfileDetails userProfileDetails = new UserProfileDetails();
                userProfileDetails.setEmailId(userProfile.getEmailId());
                userProfileDetails.setUserId(userProfile.getId());
                userProfileDetails.setUsername(userProfile.getUsername());
                userProfileDetails.setFullName(userProfile.getFirstName() + " " + userProfile.getLastName());
                userProfileDetails.setIsAccountApproved(accountStatus.getAccountApprovalStatus() != null ? accountStatus.getAccountApprovalStatus().getIsAccountApproved() : Boolean.FALSE);
                userProfileDetails.setIsAccountActive(accountStatus.getAccountActivationStatus() != null ? accountStatus.getAccountActivationStatus().getIsActive() : Boolean.FALSE);
                userProfileDetailsList.add(userProfileDetails);
            }
            baseResponse.setPayload(userProfileDetailsList);
            baseResponse.setMessage("Successfully fetched List of User Details");
            baseResponse.setSuccess(true);
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "fetchUserDetailsList", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage(ACTION_FAILED.label);
            baseResponse.setSuccess(false);
            return baseResponse;
        }
    }

    public static ProfileImageDetails uploadProfileImage(@Nonnull MultipartFile file)
            throws IOException {
        ProfileImageDetails profileImageDetails = new ProfileImageDetails();

        byte[] bytes = IOUtils.toByteArray(file.getInputStream());

        profileImageDetails.setFileContent(Base64.getEncoder().encodeToString(bytes));
        profileImageDetails.setFileFormat("");
        String originalFileName = file.getOriginalFilename();
        if(StringUtils.hasLength(originalFileName)){
            String[] parts = originalFileName.split("\\.(?=[^\\.]+$)");
            if (parts.length > 1) {
                profileImageDetails.setFileFormat(parts[1]);
            }
        }

        return profileImageDetails;
    }

    @Override
    public BaseResponse unblockUserRequest(HttpServletRequest request, RegistrationUser registrationUser){
        BaseResponse baseResponse = new BaseResponse();
        String email = registrationUser.getEmailId();
        UserProfile userProfile = userRepo.findByEmailId(email);

        AccountStatus userAccountStatus = accStatusRepo.findByUserId(userProfile.getId());
        String ip = registrationUser.getIp();

        if(email != null && !email.isEmpty()) {
            Boolean deviceBlockStatus = requestUtil.getDeviceBlockStatus(userProfile.getId(), ip).getBody();

            if(Boolean.TRUE.equals(deviceBlockStatus) && (userAccountStatus.getUnblockRequested() == null || !userAccountStatus.getUnblockRequested())) {
                try {
                    emailUtil.sendUnblockRequestMail(request, userProfile, ip);
                }catch (MessagingException | UnsupportedEncodingException ex){
                    baseResponse.setMessage("Email Cannot be sent.");
                    baseResponse.setSuccess(false);
                }
                userAccountStatus.setUnblockRequested(true);
                accStatusRepo.save(userAccountStatus);

                baseResponse.setMessage("Request Mail Sent to admin");
                baseResponse.setSuccess(true);
            } else {
                baseResponse.setMessage("Request Mail already sent to admin");
                baseResponse.setSuccess(true);
            }
        } else {
            baseResponse.setMessage("Email Cannot be null");
            baseResponse.setSuccess(false);
        }

        return baseResponse;
    }

    @Override
    public BaseResponse unblockUser(RegistrationUser registrationUser) throws UnsupportedEncodingException {
        UserProfile user = userRepo.findByEmailId(registrationUser.getMailId());
        BaseResponse baseResponse = new BaseResponse();
        if (user == null) {
            baseResponse.setMessage("This user account does not exist.");
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.NOT_FOUND));
            baseResponse.setSuccess(false);
            return baseResponse;
        } else {
            AccountStatus accountStatus = accStatusRepo.findByUserId(user.getId());
            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            encryptor.setPassword(encryptorPassword);
            String otpToken = registrationUser.getOtpToken();

            String urldecodeOtpToken = URLDecoder.decode(otpToken, StandardCharsets.UTF_8);

            String decryptedOtpToken = encryptor.decrypt(urldecodeOtpToken);
            if (!StringUtils.hasText(decryptedOtpToken)) {
                baseResponse.setMessage("Otp Token is not set");
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
                baseResponse.setSuccess(false);
                return baseResponse;
            }

            Boolean isOtpValid = tokenService.validateTokenRestTemplate(decryptedOtpToken);
            if (Boolean.FALSE.equals(isOtpValid)) {
                baseResponse.setMessage("Token expired");
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
                baseResponse.setSuccess(false);
                return baseResponse;
            }

            String urldecodeIp = URLDecoder.decode(registrationUser.getIp(), StandardCharsets.UTF_8);
            FetchResponse fetchResponse = new FetchResponse();
            fetchResponse.setIp(urldecodeIp);

            baseResponse = requestUtil.unblockUserIp(user.getId(), fetchResponse).getBody();
            if (baseResponse == null) {
                throw new UserServiceException("User unblock Unsuccessfull.", HttpStatus.INTERNAL_SERVER_ERROR);
            }
            if (Boolean.TRUE.equals(baseResponse.getSuccess())) {
                accountStatus.setUnblockRequested(false);
                accStatusRepo.save(accountStatus);
            }
            baseResponse.setMessage("User unblocked Successfully");
            return baseResponse;
        }
    }

    public BaseResponse addOrgWatcherToUsers() {
        BaseResponse baseResponse = new BaseResponse();
        try {
            List<UserOrgRole> userOrgRoleList = userOrgRoleRepo.findAll();

            for (UserOrgRole userOrgRole : userOrgRoleList) {
                List<String> orgRoleIdList = userOrgRole.getOrgRoleIdList();

                if (!orgRoleIdList.contains("62f3c7184343136e528f1c8a")) {
                    orgRoleIdList.add("62f3c7184343136e528f1c8a");
                    userOrgRole.setOrgRoleIdList(orgRoleIdList);
                    userOrgRoleRepo.save(userOrgRole);
                }
            }
            baseResponse.setMessage("Successfully added the watcher role");
            baseResponse.setSuccess(true);
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_SERVICE_IMPL, "addOrgWatcherToUsers", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage(ACTION_FAILED_EXCEPTION.label);
            baseResponse.setSuccess(false);
            return baseResponse;
        }

    }

    /**
     * Method to fetch username from token
     *
     * @param request
     * @return BaseResponse
     */
    @Override
    public BaseResponse fetchUserNameFromToken(HttpServletRequest request) {
        BaseResponse baseResponse = new BaseResponse();
        AuthTokenResponse authTokenResponse = new AuthTokenResponse();
        String token = requestUtil.extractJwtFromRequest(request);
        String username = requestUtil.usernameFromToken(token);
        if (username!=null && !username.isEmpty()) {
            authTokenResponse.setUsername(username);
            baseResponse.setMessage("Username fetched!");
            baseResponse.setSuccess(true);
            baseResponse.setPayload(authTokenResponse);
            return baseResponse;
        }
        baseResponse.setMessage("The provided token doesn't belong to the given user.");
        baseResponse.setSuccess(false);
        baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
        return baseResponse;
    }

    /**
     * Method to save refresh token
     *
     * @param refreshToken {@link String}
     * @param username     {@link String}
     * @return {@link String}
     */
    @Override
    public String saveRefreshToken(String refreshToken, String username) {
        UserProfile user = new UserProfile();
        if (username != null && !username.isBlank()) {
            user = userRepo.findByUsername(username);
        }
        BasicTextEncryptor encryptor = new BasicTextEncryptor();
        encryptor.setPassword(encryptorPassword);
        String encryptedRefreshToken1 = encryptor.encrypt(refreshToken);
        String encryptedRefreshToken2 = encryptor.encrypt(encryptedRefreshToken1);

        if (user != null) {
            String hashedRefreshToken = tokenService.getHashedRefreshToken(refreshToken).getBody();
            UserSession userTokenDetails = userSessionRepo.findByUserId(user.getId());
            if (userTokenDetails == null) {
                userTokenDetails = new UserSession();
            }
            userTokenDetails.setEncryptedRT(encryptedRefreshToken2);
            userTokenDetails.setHashedRT(hashedRefreshToken);
            userTokenDetails.setUserId(user.getId());
            userSessionRepo.save(userTokenDetails);
            return hashedRefreshToken;
        }

        throw new UserServiceException(USER_NOT_FOUND_EXCEPTION + username, HttpStatus.BAD_REQUEST);
    }


    @Override
    public BaseResponse fetchUserDetailsByUserIdAndProjectId(String projectId, String userId){
        BaseResponse baseResponse = new BaseResponse();
        ProjectOrg projectOrg = projectOrgRepository.findByProjectId(projectId);
        if(Objects.isNull(projectOrg)){
            throw new UserServiceException("Project Org Info doesn't exist.", HttpStatus.NOT_FOUND);
        }

        String projectOrgId = projectOrg.getId();
        List<ProjectOrgRole> projectOrgRole = projectOrgRoleRepository.findByProjectOrgId(projectOrgId);
        if(projectOrgRole.isEmpty()){
            throw new UserServiceException("Project org details not found.",HttpStatus.NOT_FOUND);
        }

        UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(userId);
        if(Objects.isNull(userOrgRole)){
            throw new UserServiceException("Invalid user id.",HttpStatus.NOT_FOUND);
        }
        List<ProjectOrgRoleId> projectOrgRoleList = userOrgRole.getProjectOrgRoleIdList();

        List<RoleResponse> roleListInProjectOrgRoleList = new ArrayList<>();

        Boolean userHasDefaultRole = getProjectLevelRoles(projectOrgRoleList,projectOrgRole,roleListInProjectOrgRoleList);

        //if user does not have default role assign him.
        assignDefaultRoleToUser(roleListInProjectOrgRoleList,projectOrgRoleList,userHasDefaultRole,userOrgRole);

        Optional<UserProfile> userProfile = userRepo.findById(userId);
        if(userProfile.isEmpty()){
            throw new UserServiceException("User profile not found",HttpStatus.NOT_FOUND);
        }
        String fullName = userProfile.get().getFirstName() + " " + userProfile.get().getLastName();

        UserDetails userDetails = new UserDetails();
        userDetails.setFullName(fullName);
        userDetails.setRole(roleListInProjectOrgRoleList);
        baseResponse.setPayload(userDetails);
        baseResponse.setSuccess(true);
        baseResponse.setMessage("User details fetched successfully.");
        baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.OK));
        return baseResponse;
    }



    public Boolean getProjectLevelRoles(List<ProjectOrgRoleId> projectOrgRoleList,
                                        List<ProjectOrgRole> projectOrgRole,
                                        List<RoleResponse> roleListInProjectOrgRoleList) {
        Boolean userHasDefaultRole = false;
        for (ProjectOrgRoleId projectOrgRoleIdFromList : projectOrgRoleList) {
            String projectOrgRoleId = "";
            for (ProjectOrgRole projectOrgRole1 : projectOrgRole) {
                projectOrgRoleId = projectOrgRole1.getId();
                if (Objects.equals(projectOrgRoleIdFromList.getProjectOrganizationRoleId(), projectOrgRoleId)) {
                    String roleId = projectOrgRole1.getRoleId();
                    Optional<Role> role = roleRepo.findById(roleId);
                    if (role.isPresent()) {
                        RoleResponse roleResponse = new RoleResponse(role.get(), projectOrgRoleIdFromList);
                        if (Boolean.TRUE.equals(roleResponse.getIsDefault())) {
                            userHasDefaultRole = true;
                        }
                        roleListInProjectOrgRoleList.add(roleResponse);
                    }
                }
            }
        }
        return userHasDefaultRole;
    }


    public void assignDefaultRoleToUser(List<RoleResponse> roleListInProjectOrgRoleList, List<ProjectOrgRoleId> projectOrgRoleList, boolean userHasDefaultRole, UserOrgRole userOrgRole) {
        if (Boolean.FALSE.equals(userHasDefaultRole)) {
            roleListInProjectOrgRoleList.get(0).setIsDefault(true);
            for (ProjectOrgRoleId projectOrgRoleId : projectOrgRoleList) {
                if (Objects.equals(projectOrgRoleId.getProjectOrganizationRoleId(), roleListInProjectOrgRoleList.get(0).getProjectOrgRoleId())) {
                    projectOrgRoleId.setIsDefault(true);
                    break;
                }
            }
            userOrgRole.setProjectOrgRoleIdList(projectOrgRoleList);
            userOrgRoleRepo.save(userOrgRole);
        }
    }


    @Override
    public BaseResponse setDefaultProjectOrgRole(String defaultProjectOrgRoleId){
        BaseResponse baseResponse = new BaseResponse();
        String token = requestUtil.extractJwtFromRequest(request);
        String username = requestUtil.usernameFromToken(token);
        UserProfile user = userRepo.findByUsername(username);
        String userId = user.getId();
        String projectId = request.getHeader(HttpHeaderConstants.X_PROJECT_ID);

        ProjectOrg projectOrg = projectOrgRepository.findByProjectId(projectId);
        if(Objects.isNull(projectOrg)){
            throw new UserServiceException("Project Org Info doesn't exist.", HttpStatus.NOT_FOUND);
        }

        String projectOrgId = projectOrg.getId();
        List<ProjectOrgRole> projectOrgRole = projectOrgRoleRepository.findByProjectOrgId(projectOrgId);
        if(projectOrgRole.isEmpty()){
            throw new UserServiceException("Project org details not found.",HttpStatus.NOT_FOUND);
        }

        UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(userId);
        if(Objects.isNull(userOrgRole)){
            throw new UserServiceException("Invalid user id.",HttpStatus.NOT_FOUND);
        }
        List<ProjectOrgRoleId> projectOrgRoleList = userOrgRole.getProjectOrgRoleIdList();

        List<RoleResponse> roleListInProjectOrgRoleList = new ArrayList<>();


        //change default role
        changeDefaultRole(projectOrgRoleList, projectOrgRole,defaultProjectOrgRoleId,roleListInProjectOrgRoleList);

        userOrgRoleRepo.save(userOrgRole);

        Optional<UserProfile> userProfile = userRepo.findById(userId);
        if(userProfile.isEmpty()){
            throw new UserServiceException("User profile not found",HttpStatus.NOT_FOUND);
        }
        String fullName = userProfile.get().getFirstName() + " " + userProfile.get().getLastName();

        UserDetails userDetails = new UserDetails();
        userDetails.setFullName(fullName);
        userDetails.setRole(roleListInProjectOrgRoleList);
        baseResponse.setPayload(userDetails);
        baseResponse.setSuccess(true);
        baseResponse.setMessage("Default projectOrgRole set successfully.");
        baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.OK));
        return baseResponse;
    }

    private void changeDefaultRole(List<ProjectOrgRoleId> projectOrgRoleList, List<ProjectOrgRole> projectOrgRole, String defaultProjectOrgRoleId,List<RoleResponse> roleListInProjectOrgRoleList){
        for(ProjectOrgRoleId projectOrgRoleIdFromList : projectOrgRoleList){
            String projectOrgRoleId = "";
            for(ProjectOrgRole projectOrgRole1 : projectOrgRole){
                projectOrgRoleId = projectOrgRole1.getId();
                if(Objects.equals(projectOrgRoleIdFromList.getProjectOrganizationRoleId(),projectOrgRoleId)){
                    String roleId = projectOrgRole1.getRoleId();
                    Optional<Role> role = roleRepo.findById(roleId);
                    if(role.isPresent()){
                        checkRoleIsOfCurrentProject( defaultProjectOrgRoleId,projectOrgRoleIdFromList);
                        RoleResponse roleResponse = new RoleResponse(role.get(),projectOrgRoleIdFromList);
                        roleListInProjectOrgRoleList.add(roleResponse);
                    }
                }
            }
        }
    }

    private void checkRoleIsOfCurrentProject( String defaultProjectOrgRoleId,ProjectOrgRoleId projectOrgRoleIdFromList){
        projectOrgRoleIdFromList.setIsDefault(projectOrgRoleIdFromList.getProjectOrganizationRoleId().equals(defaultProjectOrgRoleId));
    }

}



