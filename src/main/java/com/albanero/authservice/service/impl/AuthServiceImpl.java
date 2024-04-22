package com.albanero.authservice.service.impl;

import com.albanero.authservice.common.constants.*;
import com.albanero.authservice.common.dto.request.AuthRequest;
import com.albanero.authservice.common.dto.request.SecurityQuesRequest;
import com.albanero.authservice.common.dto.request.UserIdDetails;
import com.albanero.authservice.common.dto.response.*;
import com.albanero.authservice.common.util.EmailUtil;
import com.albanero.authservice.common.util.HelperUtil;
import com.albanero.authservice.common.util.RequestUtil;
import com.albanero.authservice.exception.AuthServiceException;
import com.albanero.authservice.model.*;
import com.albanero.authservice.repository.*;
import com.albanero.authservice.service.*;
import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.jasypt.util.text.BasicTextEncryptor;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.devtools.restart.Restarter;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.*;

import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.*;
import static com.albanero.authservice.common.constants.LoggerConstants.*;
import static com.albanero.authservice.common.constants.ResponseMessageConstants.VALID_TOKEN_GENERATED;

/**
 * Authentication Service Implementation to provide logic to the controller
 *
 * @author arunima.mishra
 */
@Service
@RefreshScope
@Slf4j
public class AuthServiceImpl implements UserDetailsService, AuthenticationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthServiceImpl.class);

    public static final String ROLE_ADMIN = "ROLE_ADMIN";

    private static final SecureRandom secureRandom = new SecureRandom();

    private static final String AUTH_SERVICE_IMPL_CLASS = "AuthServiceImpl";

    @Value("${jasyptSecret}")
    private String encryptorPassword;

    private final AuthenticationManager authenticationManager;

    private final UserRepository userRepo;

    private final ProductRepository prodRepo;

    private final UserOrgRoleRepository userOrgRoleRepo;

    private final SecurityQuestionsRepository securityQuestionsRepository;

    private final UserRoleService userRoleService;

    private final AccStatusRepository accStatusRepo;

    private final MfaStatusRepository mfaRepo;

    private final SQStatusRepository sqRepo;

    private final UserSessionRepository userSessionRepo;

    private final PasswordEncoder bcryptEncoder;

    private final RequestUtil requestUtil;

    private final HelperUtil helperUtil;

    private final UserService userService;

    private final EmailUtil emailUtil;

    private final TokenService tokenService;

    private final RBAService rbaService;

    @Autowired
    public AuthServiceImpl(AuthenticationManager authenticationManager, UserRepository userRepo, ProductRepository prodRepo, UserOrgRoleRepository userOrgRoleRepo, SecurityQuestionsRepository securityQuestionsRepository, UserRoleService userRoleService, AccStatusRepository accStatusRepo, MfaStatusRepository mfaRepo, SQStatusRepository sqRepo, UserSessionRepository userSessionRepo, PasswordEncoder bcryptEncoder, RequestUtil requestUtil, HelperUtil helperUtil, UserService userService, EmailUtil emailUtil, TokenService tokenService, RBAService rbaService) {
        this.authenticationManager = authenticationManager;
        this.userRepo = userRepo;
        this.prodRepo = prodRepo;
        this.userOrgRoleRepo = userOrgRoleRepo;
        this.securityQuestionsRepository = securityQuestionsRepository;
        this.userRoleService = userRoleService;
        this.accStatusRepo = accStatusRepo;
        this.mfaRepo = mfaRepo;
        this.sqRepo = sqRepo;
        this.userSessionRepo = userSessionRepo;
        this.bcryptEncoder = bcryptEncoder;
        this.requestUtil = requestUtil;
        this.helperUtil = helperUtil;
        this.userService = userService;
        this.emailUtil = emailUtil;
        this.tokenService = tokenService;
        this.rbaService = rbaService;
    }

    /**
     * @param request               {@link HttpServletRequest}
     * @param authenticationRequest {@link AuthRequest}
     * @return {@link BaseResponse}
     */
    @Override
    public BaseResponse authenticate(HttpServletRequest request, AuthRequest authenticationRequest) {
        String method = "authenticate";
        BaseResponse baseResponse = new BaseResponse();
        AuthResponse authResponse = new AuthResponse();
        UserIdDetails userIdDetails = new UserIdDetails();
        FetchResponse requestDetails = rbaService.fetchRequestDetails(request);

        UserProfile userProfileDetails = userRepo.findByEmailOrUserName(authenticationRequest.getUsername());
        if (Objects.isNull(userProfileDetails)) {
            throw new AuthServiceException("User not found with the username or email:" + authenticationRequest.getUsername(), HttpStatus.NOT_FOUND);
        }

        // Validate user credentials
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(userProfileDetails.getUsername(),
                        authenticationRequest.getPassword())
        );

        // Check user Account Status
        UserProfile userProfile = loadUserProfileByUsername(userProfileDetails.getUsername());
        AccountStatus accStatus = accStatusRepo.findByUserId(userProfile.getId());
        String userAccountStatus = HelperUtil.getUserAccountStatus(accStatus);
        if (!Objects.equals(userAccountStatus, AuthConstants.ACCOUNT_ACTIVE)) {
            incrementFailedAttempts(userProfile.getId(), requestDetails);
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG, AUTH_SERVICE_IMPL_CLASS, method, "User account status is not active.", "UserId", userProfile.getId());
            throw new AuthServiceException(userAccountStatus, HttpStatus.FORBIDDEN);
        }

        // Check for User Block Status
        List<String> userIds = new ArrayList<>();
        userIds.add(userProfile.getId());
        BaseResponse usersBlockStatus = requestUtil.getUsersBlockStatus(userIds);
        if (Boolean.TRUE.equals(usersBlockStatus.getSuccess())) {
            ObjectMapper mapper = new ObjectMapper();
            List<UserBlockStatusDto> userBlockStatusList = List.of(mapper.convertValue(usersBlockStatus.getPayload(), UserBlockStatusDto[].class));
            Boolean status = HelperUtil.getBlockStatus(userBlockStatusList, userProfile.getId());
            if (Boolean.TRUE.equals(status)) {
                throw new AuthServiceException(IP_BLOCK_EXCEPTION, HttpStatus.FORBIDDEN);
            }
        }

        // Check for Security Question
        validateUserSecuirtyQuestion(userProfile, baseResponse);

        // Check for risk level
        BaseResponse riskCheckResponse = riskLevelCheck(userProfile, requestDetails);
        if (!riskCheckResponse.getSuccess().equals(true)) {
            if (riskCheckResponse.getPayload() != null) {
                throw new AuthServiceException(RISK_LEVE_CALCULATION_ERROR, HttpStatus.INTERNAL_SERVER_ERROR);
            } else {
                throw new AuthServiceException(riskCheckResponse.getMessage(), HttpStatus.FORBIDDEN);
            }
        }

        // USER ROLE AND PERMISSIONS
        UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(userProfile.getId());
        if (userOrgRole != null) {
            userRoleService.setUserIdDetails(userProfile, userIdDetails);
        } else {
            incrementFailedAttempts(userProfile.getUsername(), requestDetails);
            throw new AuthServiceException(ROLE_NOT_ASSIGNED_EXCEPTION, HttpStatus.FORBIDDEN);
        }

        // fetch and check for existence of all the roles and permissions
        UserIdDetails userRoleDetails = userRoleService.fetchUserIdDetails(userOrgRole, authenticationRequest, userProfile);


        // check for 2FA
        MfaStatus mfaDetails = mfaRepo.findByUserId(userProfile.getId());
        if (mfaDetails.getIsEnabled() != null && mfaDetails.getIsEnabled()) {
            String otpToken = requestUtil.verificationToken(userProfile.getEmailId(), TokenConstants.OTP_TOKEN_DURATION);
            String fetchResponseToken = requestUtil.getFetchResponseToken(userProfile.getEmailId(), requestDetails);
            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            encryptor.setPassword(encryptorPassword);
            String encryptedOtpToken = encryptor.encrypt(otpToken);
            authResponse.setOtpToken(encryptedOtpToken);
            authResponse.setIs2faEnabled(true);
            authResponse.setFetchResponseToken(fetchResponseToken);
            authResponse.setAlbaUser(userProfile.getFirstName() + " " + userProfile.getLastName());
            authResponse.setReason(AuthenticationFailureConstants.MFA);
            throw new AuthServiceException(OTP_VERIFICATION_EXCEPTION, authResponse, HttpStatus.OK);
        }

        ResponseEntity<String> jwtTokenResponse = tokenService.generateAccessToken(userIdDetails);
        String jwtToken = jwtTokenResponse.getBody();

        ResponseEntity<String> refreshTokenResponse = tokenService.generateRefreshToken(userIdDetails);
        String refreshToken = refreshTokenResponse.getBody();

        String hashedRefreshToken = userService.saveRefreshToken(refreshToken, userProfileDetails.getUsername());
        BasicTextEncryptor encryptor = new BasicTextEncryptor();
        encryptor.setPassword(encryptorPassword);
        String encryptedJwtToken = encryptor.encrypt(jwtToken);

        resetFailedAttempts(userProfile.getId());


        return setAuthResponse(
                baseResponse,
                authResponse,
                userProfile,
                hashedRefreshToken,
                encryptedJwtToken,
                userRoleDetails
        );
    }

    private void validateUserSecuirtyQuestion(UserProfile userProfile, BaseResponse baseResponse) {
        SecurityQuestionStatus secStatus = sqRepo.findByUserId(userProfile.getId());
        if (Boolean.TRUE.equals(secStatus != null &&
                secStatus.getIsUsingSQ() != null &&
                secStatus.getIsUsingSQ()) &&
                secStatus.getQuestion() != null
        ) {
            SecurityQuesRequest securityQuesRequest = new SecurityQuesRequest();
            securityQuesRequest.setIsUsingSQ(true);
            securityQuesRequest.setQuestion(secStatus.getQuestion());
            securityQuesRequest.setReason(AuthenticationFailureConstants.SQ);
            baseResponse.setPayload(securityQuesRequest);
            throw new AuthServiceException(SECURITY_QUESTION_VERIFY_EXCEPTION, securityQuesRequest, HttpStatus.OK);
        }
    }

    /**
     * @param request               {@link HttpServletRequest}
     * @param authenticationRequest {@link AuthRequest}
     * @return {@link BaseResponse}
     */
    @Override
    public BaseResponse authenticateMFA(HttpServletRequest request, AuthRequest authenticationRequest) {
        BaseResponse baseResponse = new BaseResponse();
        AuthResponse authResponse = new AuthResponse();
        FetchResponse requestDetails = rbaService.fetchRequestDetails(request);

        UserProfile userProfile = loadUserProfileByMailId(authenticationRequest.getEmailId());
        AccountStatus accStatus = accStatusRepo.findByUserId(userProfile.getId());

        // Check for rick level
        BaseResponse riskCheckResponse = riskLevelCheck(userProfile, requestDetails);
        if (!riskCheckResponse.getSuccess().equals(true)) {
            if (riskCheckResponse.getPayload() != null) {
                throw new AuthServiceException(RISK_LEVE_CALCULATION_ERROR, HttpStatus.INTERNAL_SERVER_ERROR);
            } else {
                throw new AuthServiceException(riskCheckResponse.getMessage(), HttpStatus.FORBIDDEN);
            }
        }

        // Check user Account Status
        String userAccountStatus = HelperUtil.getUserAccountStatus(accStatus);
        if (!Objects.equals(userAccountStatus, AuthConstants.ACCOUNT_ACTIVE)) {
            incrementFailedAttempts(userProfile.getId(), requestDetails);
            throw new AuthServiceException(userAccountStatus, HttpStatus.FORBIDDEN);
        }

        // Check for Security Question
        validateUserSecuirtyQuestion(userProfile, baseResponse);

        String otpToken = requestUtil.verificationToken(userProfile.getEmailId(), TokenConstants.OTP_TOKEN_DURATION);
        String fetchResponseToken = requestUtil.getFetchResponseToken(userProfile.getEmailId(), requestDetails);

        BasicTextEncryptor encryptor = new BasicTextEncryptor();
        encryptor.setPassword(encryptorPassword);
        String encryptedOtpToken = encryptor.encrypt(otpToken);

        authResponse.setIs2faEnabled(true);
        authResponse.setOtpToken(encryptedOtpToken);
        authResponse.setToken(fetchResponseToken);
        authResponse.setAlbaUser(userProfile.getFirstName() + " " + userProfile.getLastName());
        authResponse.setReason(AuthenticationFailureConstants.MFA);

        throw new AuthServiceException(OTP_VERIFICATION_EXCEPTION, authResponse, HttpStatus.OK);
    }

    /**
     * Method to load user details by username
     *
     * @param username {@link String}
     * @return {@link UserDetails}
     */
    @Override
    public UserDetails loadUserByUsername(String username) {
        UserProfile user = userRepo.findByUsername(username);
        if (user != null) {
            List<SimpleGrantedAuthority> roles = List.of(new SimpleGrantedAuthority(user.getRole()));
            return new User(user.getUsername(), user.getPassword(), roles);
        }
        log.error("User not found with the name {}", username);
        throw new BadCredentialsException("User not found for the given username");
    }

    public UserProfile loadUserProfileByUsername(String username) {
        UserProfile user = userRepo.findByUsername(username);
        if (user != null) {
            return user;
        }
        log.error("User not found with the name {}", username);
        throw new BadCredentialsException("User not found for the given username");
    }

    public UserProfile loadUserProfileByMailId(String mail) throws UsernameNotFoundException {
        UserProfile user = userRepo.findByEmailId(mail.toLowerCase());
        if (user != null) {
            return user;
        }
        log.error("User not found with the mail ID {}", mail);
        throw new BadCredentialsException("User not found with the given mail ID");
    }


    public UserProfile loadUserProfileByUsernameOrEmail(String identifier) {
        UserProfile userProfileDetails = userRepo.findByEmailOrUserName(identifier);
        if (Objects.isNull(userProfileDetails)) {
            throw new BadCredentialsException("User not found with the username or email:" + identifier);
        }
        return userProfileDetails;
    }


    /**
     * Method to load user details by userProfile
     *
     * @param userProfile {@link UserProfile}
     * @return {@link UserDetails}
     */
    @Override
    public UserDetails loadUserByUserProfile(UserProfile userProfile) throws UsernameNotFoundException {
        if (userProfile != null && userProfile.getRole() != null) {
            List<SimpleGrantedAuthority> roles = List.of(new SimpleGrantedAuthority(userProfile.getRole()));
            return new User(userProfile.getUsername(), userProfile.getPassword(), roles);
        }
        throw new BadCredentialsException("User not found with the profile " + userProfile);
    }

    /**
     * Method to save refresh token
     *
     * @param refreshToken {@link String}
     * @param username     @link String}
     * @return {@link String}
     */
    @Override
    public String saveRefreshTokenAfterGLogin(String refreshToken, String username) {
        return userService.saveRefreshToken(refreshToken, username);
    }

    /**
     * Method to invalidate a refresh token
     *
     * @param username {@link String}
     */
    public void invalidateExistingRefreshToken(String username) {
        try {
            UserProfile user = userRepo.findByUsername(username);
            UserSession userTokenDetails = userSessionRepo.findByUserId(user.getId());
            String encryptedRT = userTokenDetails.getEncryptedRT();
            String hashedRT = userTokenDetails.getHashedRT();
            if (encryptedRT == null || hashedRT == null || hashedRT.isEmpty() || encryptedRT.isEmpty())
                return;
            userTokenDetails.setEncryptedRT(generateSecretKey());
            userTokenDetails.setHashedRT(generateSecretKey());
            userRepo.save(user);

        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, AUTH_SERVICE_IMPL_CLASS, "invalidateExistingRefreshToken", e.getMessage(), e.getStackTrace());
        }
    }

    /**
     * Method to generate access and refresh tokens
     *
     * @param username {@link String}
     * @return AuthResponse {@link AuthResponse}
     */
    @Override
    public AuthResponse generateToken(String username) {
        AuthResponse authResponse = new AuthResponse();
        try {

            UserProfile userProfile = loadUserProfileByUsername(username);
            invalidateExistingRefreshToken(username);

            String jwtToken = requestUtil.jwtTokenFromUserProfile(userProfile, TokenConstants.ACCESS);
            String refreshToken = requestUtil.jwtTokenFromUserProfile(userProfile, TokenConstants.REFRESH);
            String hashedRefreshToken = saveRefreshTokenAfterGLogin(refreshToken, username);

            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            encryptor.setPassword(encryptorPassword);
            jwtToken = encryptor.encrypt(jwtToken);
            authResponse.setToken(jwtToken);
            authResponse.setRefreshToken(hashedRefreshToken);
            return authResponse;
        } catch (UsernameNotFoundException e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, AUTH_SERVICE_IMPL_CLASS, "generateToken", e.getMessage(), e.getStackTrace());
            throw new AuthServiceException("User not found", HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Method to verify the OTP for MFA
     *
     * @param verifyCodeRequest {@link AuthResponse}
     * @return {@link BaseResponse}
     */
    @Override
    public BaseResponse verify(AuthRequest verifyCodeRequest) {
        BaseResponse baseResponse = new BaseResponse();
        AuthResponse authResponse = new AuthResponse();
        UserIdDetails userIdDetails = new UserIdDetails();
        BasicTextEncryptor encryptor = new BasicTextEncryptor();
        encryptor.setPassword(encryptorPassword);
        String decryptedOtpToken = encryptor.decrypt(verifyCodeRequest.getOtpToken());

        Boolean isOtpValid = tokenService.validateTokenRestTemplate(decryptedOtpToken);

        ResponseEntity<FetchResponse> fetchResponseEntity = tokenService.getFetchResponseFromToken(verifyCodeRequest.getFetchResponseToken());

        String usermail = requestUtil.getEmailFromToken(decryptedOtpToken);
        UserProfile userProfile = userRepo.findByEmailId(usermail);

        if (Boolean.FALSE.equals(isOtpValid)) {
            incrementFailedAttempts(userProfile.getId(), fetchResponseEntity.getBody());
            baseResponse.setMessage("OTP has expired");
            baseResponse.setSuccess(false);
            return baseResponse;
        }
        BaseResponse riskCheckResponse = riskLevelCheck(userProfile, fetchResponseEntity.getBody());
        if (riskCheckResponse.getSuccess().equals(true)) {
            baseResponse.setSuccess(true);
        } else {
            if (riskCheckResponse.getPayload() != null) {
                authResponse.setReason(AuthenticationFailureConstants.RBA);
                authResponse.setToken(riskCheckResponse.getPayload().toString());
                baseResponse = riskCheckResponse;
                baseResponse.setPayload(authResponse);
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.FORBIDDEN));
                return baseResponse;
            } else {
                return riskCheckResponse;
            }
        }

        MfaStatus mfaStatus = mfaRepo.findByUserId(userProfile.getId());
        // call mfa service to verify code
        ResponseEntity<Boolean> isValidCode = requestUtil.verifyFromMfaService(verifyCodeRequest.getVerificationCode(), mfaStatus.getMfa().getMfaSecret());
        if (Boolean.FALSE.equals(isValidCode.getBody())) {
            incrementFailedAttempts(userProfile.getId(), fetchResponseEntity.getBody());
            baseResponse.setMessage("Incorrect Verification Code!");
            baseResponse.setSuccess(false);
            return baseResponse;
        }

        invalidateExistingRefreshToken(userProfile.getUsername());
        SecurityQuestionStatus sqStatus = sqRepo.findByUserId(userProfile.getId());
        // check for Security Question
        if (Boolean.TRUE.equals(sqStatus != null && sqStatus.getIsUsingSQ() != null && sqStatus.getIsUsingSQ()) && sqStatus.getQuestion() != null) {
            baseResponse.setMessage("The user is required to go for Security Question Verification.");
            SecurityQuesRequest securityQuesRequest = new SecurityQuesRequest();
            securityQuesRequest.setIsUsingSQ(true);
            securityQuesRequest.setQuestion(sqStatus.getQuestion());
            securityQuesRequest.setReason(AuthenticationFailureConstants.SQ);
            baseResponse.setPayload(securityQuesRequest);
            baseResponse.setSuccess(false);
            return baseResponse;
        }

        UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(userProfile.getId());
        if (userOrgRole != null)
            userRoleService.setUserIdDetails(userProfile, userIdDetails);
        else {
            authResponse.setReason(AuthenticationFailureConstants.LOGOUT);
            baseResponse.setMessage(ROLE_NOT_ASSIGNED_EXCEPTION.label);
            baseResponse.setSuccess(false);
            return baseResponse;
        }

        // fetch and check for existence of all the roles and permissions
        UserIdDetails userRoleDetails = userRoleService.fetchUserIdDetails(userOrgRole, verifyCodeRequest, userProfile);

        String jwtToken = requestUtil.jwtToken(userIdDetails, TokenConstants.ACCESS);
        String refreshToken = requestUtil.jwtToken(userIdDetails, TokenConstants.REFRESH);

        String hashedRefreshToken = userService.saveRefreshToken(refreshToken, userProfile.getUsername());
        String encryptedJwtToken = encryptor.encrypt(jwtToken);

        resetFailedAttempts(userProfile.getId());

        return setAuthResponse(
                baseResponse,
                authResponse,
                userProfile,
                hashedRefreshToken,
                encryptedJwtToken,
                userRoleDetails
        );
    }

    /**
     * Method to check if MFA is enabled in case of google login
     *
     * @param usermail {@link String}
     * @return {@link Boolean}
     */
    @Override
    public Boolean checkForMfa(String usermail) {
        UserProfile user = userRepo.findByEmailId(usermail.toLowerCase());
        MfaStatus mfaStatus = mfaRepo.findByUserId(user.getId());
        try {
            return mfaStatus.getIsEnabled();
        } catch (Exception e) {
            LOGGER.warn(AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG, AUTH_SERVICE_IMPL_CLASS, "checkForMfa", e.getMessage(), e.getStackTrace());
            return false;
        }
    }

    /**
     * Method to check if MFA is enabled
     *
     * @param request {@link HttpServletRequest}
     * @return {@link Boolean}
     */
    @Override
    public Boolean checkMfa(HttpServletRequest request) {
        try {
            String token = requestUtil.extractJwtFromRequest(request);
            String username = requestUtil.usernameFromToken(token);
            UserProfile user = userRepo.findByUsername(username);
            MfaStatus mfaStatus = mfaRepo.findByUserId(user.getId());
            if (mfaStatus != null && mfaStatus.getIsEnabled() != null)
                return mfaStatus.getIsEnabled();
            return false;
        } catch (Exception e) {
            LOGGER.warn(AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG, AUTH_SERVICE_IMPL_CLASS, "checkMfa", e.getMessage(), e.getStackTrace());
            return false;
        }
    }

    /**
     * Method to restart the application
     */
    public void restartApp() {
        Restarter.getInstance().restart();
    }

    /**
     * Method to encrypt the password for a specific user
     *
     * @param plainTextPassword {@link String}
     * @return String {@link String}
     */
    public String hashPassword(String plainTextPassword) {
        try {
            return BCrypt.hashpw(plainTextPassword, BCrypt.gensalt());
        } catch (Exception e) {
            LOGGER.warn(AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG, AUTH_SERVICE_IMPL_CLASS, "hashPassword", e.getMessage(), e.getStackTrace());
            return null;
        }
    }

    /**
     * @param productDetails {@link List<ProductRoleDetails>}
     * @return {@link List<ProductRoles>}
     */
    @Override
    public List<ProductRoles> checkForProductLevelDetails(List<ProductRoleDetails> productDetails) {
        List<ProductRoles> productRolesList = new ArrayList<>();
        for (ProductRoleDetails productRoleDetails : productDetails) {
            ProductRoles productRoles = new ProductRoles();
            productRoles.setProductRole(productRoleDetails.getRole());
            Optional<Product> product = prodRepo.findById(productRoleDetails.getProductId());
            if (product.isPresent()) {
                productRoles.setProductName(product.get().getName());
                productRolesList.add(productRoles);
            }
        }
        return productRolesList;
    }

    @Override
    public String generateSecretKey() {
        String alphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "abcdefghijklmnopqrstuvxyz"
                + "!@#$%^&*()_+";
        StringBuilder sb = new StringBuilder(16);
        for (int i = 0; i < 16; i++) {
            int index = secureRandom.nextInt(alphaNumericString.length());
            sb.append(alphaNumericString.charAt(index));
        }
        return sb.toString();
    }

    /**
     * @param data   {@link String}
     * @param secret {@link String}
     * @return {@link String}
     * @throws Exception
     */
    public static String encrypt(String data, String secret) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        int length = secret.length();
        if (length < 16) {
            int remainderLen = 16 - length;
            if (remainderLen > 8) {
                String newSecret = secret + secret;
                remainderLen = 16 - newSecret.length();
                newSecret += secret.substring(0, remainderLen);
                secret = newSecret;
            } else
                secret += secret.substring(0, remainderLen);
        } else if (length > 16) {
            secret = secret.substring(0, 16);
        }
        String encodedBase64Key = encodeKey(secret);
        LOGGER.info("EncodedBase64Key = {}", encodedBase64Key); // This need to be share between client and server
        Key key = generateKey(encodedBase64Key);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encVal);
    }

    private static Key generateKey(String secret) {
        byte[] decoded = Base64.getDecoder().decode(secret.getBytes());
        return new SecretKeySpec(decoded, "AES/GCM/NoPadding");
    }

    public static String encodeKey(String str) {
        byte[] encoded = Base64.getEncoder().encode(str.getBytes());
        return new String(encoded);
    }

    @Override
    public BaseResponse validateAccessToken(HttpServletRequest request) {
        BaseResponse baseResponse = new BaseResponse();
        AuthTokenResponse authTokenResponse = new AuthTokenResponse();
        String token = requestUtil.extractJwtFromRequest(request);
        ObjectMapper mapper = new ObjectMapper();
        if (token != null && token.contains(".")) {
            String[] tokenSplit = token.split("\\.");
            String tokenSplitHeader = tokenSplit[0];
            byte[] decodedBytes = Base64.getDecoder().decode(tokenSplitHeader);
            String tokenHeader = new String(decodedBytes);
            if (!tokenHeader.contains("alg"))
                return validateAndThrowExceptionIfNull(authTokenResponse, baseResponse, "The provided token is not a JWT!", HttpStatus.BAD_REQUEST);
        }

        if (Boolean.TRUE.equals(tokenService.validateTokenRestTemplate(token)))
            return validateAccessTokenIfValidToken(token, authTokenResponse, baseResponse, mapper);

        authTokenResponse.setIsTokenValid(false);
        baseResponse.setMessage("Authentication token is invalid.");
        baseResponse.setSuccess(false);
        baseResponse.setPayload(authTokenResponse);
        baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
        return baseResponse;
    }

    private BaseResponse validateAccessTokenIfValidToken(String token, AuthTokenResponse authTokenResponse, BaseResponse baseResponse, ObjectMapper mapper) {
        String username = requestUtil.usernameFromToken(token);
        UserProfile user = userRepo.findByUsername(username);

        if (user == null)
            return validateAndThrowExceptionIfNull(authTokenResponse, baseResponse, "The provided user is invalid.", HttpStatus.FORBIDDEN);
        UserSession userSession = userSessionRepo.findByUserId(user.getId());
        if (userSession == null || userSession.getEncryptedRT() == null || userSession.getHashedRT() == null)
            return validateAndThrowExceptionIfNull(authTokenResponse, baseResponse, "Authentication token is invalid.", HttpStatus.FORBIDDEN);

        // Check for User Account Status
        AccountStatus accStatus = accStatusRepo.findByUserId(user.getId());
        String accountStatus = HelperUtil.getUserAccountStatus(accStatus);
        if (!Objects.equals(accountStatus, AuthConstants.ACCOUNT_ACTIVE)) {
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.FORBIDDEN));
            baseResponse.setMessage(accountStatus);
            return baseResponse;
        }

        // Check for User Block Status
        List<String> userIds = new ArrayList<>();
        userIds.add(user.getId());
        BaseResponse usersBlockStatus = requestUtil.getUsersBlockStatus(userIds);
        if (Boolean.TRUE.equals(usersBlockStatus.getSuccess())) {
            List<UserBlockStatusDto> userBlockStatusList = List.of(mapper.convertValue(usersBlockStatus.getPayload(), UserBlockStatusDto[].class));
            Boolean status = HelperUtil.getBlockStatus(userBlockStatusList, user.getId());
            if (Boolean.TRUE.equals(status)) {
                baseResponse.setSuccess(false);
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.FORBIDDEN));
                baseResponse.setMessage("User can't Authentication because this IP is blocked!");
                return baseResponse;
            }
        }

        // Validations for User Mappings
        BaseResponse userIdDetailsResponse = requestUtil.getUserMappings(token);
        UserIdDetails userIdDetails = mapper.convertValue(userIdDetailsResponse.getPayload(), UserIdDetails.class);
        baseResponse = userRoleService.validateUserMappings(userIdDetails, user);

        return baseResponse;
    }

    private static BaseResponse validateAndThrowExceptionIfNull(AuthTokenResponse authTokenResponse, BaseResponse baseResponse, String message, HttpStatus httpStatus) {
        authTokenResponse.setIsTokenValid(false);
        baseResponse.setMessage(message);
        baseResponse.setSuccess(false);
        baseResponse.setPayload(authTokenResponse);
        baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(httpStatus));
        return baseResponse;
    }

    @Override
    public String validateInternalAuthToken(String token) {
        return null;
    }


    /**
     * To Generate Internal Access Token
     *
     * @param userId      {@link String}
     * @param secretToken {@link String}
     * @return {@link BaseResponse}
     */
    @Override
    public BaseResponse generateInternalToken(String userId, String secretToken) {
        BaseResponse baseResponse = new BaseResponse();
        UserIdDetails userIdDetails = new UserIdDetails();
        AuthResponse authResponse = new AuthResponse();
        Optional<UserProfile> userProfile;
        try {
            if (secretToken == null || secretToken.isEmpty()) {
                baseResponse.setSuccess(false);
                baseResponse.setMessage("The given token is either null or empty!");
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.FORBIDDEN));
                return baseResponse;
            }
            if (userId != null && !userId.isEmpty()) {
                userProfile = userRepo.findById(userId);
                baseResponse.setSuccess(true);
                UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(userId);
                if (userOrgRole != null && userProfile.isPresent())
                    userRoleService.setUserIdDetails(userProfile.get(), userIdDetails);
                else {
                    baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.FORBIDDEN));
                    baseResponse.setMessage(ROLE_NOT_ASSIGNED_EXCEPTION.label);
                    baseResponse.setSuccess(false);
                    return baseResponse;
                }
                BaseResponse response = requestUtil.getInternalToken(secretToken, userIdDetails);
                String jwtToken = (String) response.getPayload();
                BasicTextEncryptor encryptor = new BasicTextEncryptor();
                encryptor.setPassword(encryptorPassword);
                String encryptedJwtToken = encryptor.encrypt(jwtToken);
                authResponse.setToken(encryptedJwtToken);
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.OK));
                baseResponse.setPayload(authResponse);
                baseResponse.setSuccess(true);
                baseResponse.setMessage("Token returned!");
                return baseResponse;
            }
            baseResponse.setSuccess(false);
            baseResponse.setMessage("The given user ID is either null or empty!");
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.FORBIDDEN));
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, AUTH_SERVICE_IMPL_CLASS, "generateInternalToken", e.getMessage(), e.getStackTrace());
            baseResponse.setSuccess(false);
            baseResponse.setMessage("Action Failed.");
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
            return baseResponse;
        }
    }

    /**
     * Method to check if Security questions is enabled
     *
     * @param request {@link HttpServletRequest}
     */

    public Boolean checkSQ(HttpServletRequest request) {
        String token = requestUtil.extractJwtFromRequest(request);
        String username = requestUtil.usernameFromToken(token);
        UserProfile user = userRepo.findByUsername(username);
        SecurityQuestionStatus sqStatus = sqRepo.findByUserId(user.getId());
        try {
            return sqStatus.getIsUsingSQ();
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, AUTH_SERVICE_IMPL_CLASS, "checkSQ", e.getMessage(), e.getStackTrace());
            return false;
        }
    }

    /**
     * Method to check if SecurityQuestions is enabled
     *
     * @param username {@link String}
     */
    @Override
    public BaseResponse checkForSQ(String username) {
        UserProfile user = userRepo.findByUsername(username);
        BaseResponse baseResponse = new BaseResponse();
        SecurityQuestionStatus sqStatus = sqRepo.findByUserId(user.getId());
        try {
            if (Boolean.TRUE.equals(sqStatus.getIsUsingSQ())) {

                SecurityQuestionsResponse securityQuestionsResponse = new SecurityQuestionsResponse();
                int index = 0;
                List<String> questions = securityQuestionsRepository.findAll().get(0).getQuestions();
                LOGGER.warn(AUTHENTICATION_SERVICE_INFO_LOG_TAG, AUTH_SERVICE_IMPL_CLASS, "checkForSQ", "Security Question", questions);
                if (questions != null && !questions.isEmpty()) {
                    securityQuestionsResponse.setQuestion1(questions.get(index++));
                    securityQuestionsResponse.setQuestion2(questions.get(index++));
                    securityQuestionsResponse.setQuestion3(questions.get(index++));
                    securityQuestionsResponse.setQuestion4(questions.get(index++));
                    securityQuestionsResponse.setQuestion5(questions.get(index));
                    baseResponse.setPayload(securityQuestionsResponse);
                    baseResponse.setMessage("Security Questions returned.");
                    baseResponse.setSuccess(true);
                    return baseResponse;
                }
            }
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, AUTH_SERVICE_IMPL_CLASS, "checkForSQ", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage("No question found!");
            baseResponse.setSuccess(false);
            return baseResponse;
        }
        return null;
    }

    public Boolean checkForSQ1(String username) {
        UserProfile user = userRepo.findByUsername(username);
        SecurityQuestionStatus sqStatus = sqRepo.findByUserId(user.getId());
        try {
            return sqStatus.getIsUsingSQ();
        } catch (Exception e) {
            LOGGER.warn(AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG, AUTH_SERVICE_IMPL_CLASS, "checkForSQ1", e.getMessage(), e.getStackTrace());
            return false;
        }
    }

    @Override
    public BaseResponse saveSecurityQuestion(HttpServletRequest request, SecurityQuesRequest securityQuesRequest) {
        BaseResponse baseResponse = new BaseResponse();
        String token = requestUtil.extractJwtFromRequest(request);
        String loggedInUsername = requestUtil.usernameFromToken(token);

        UserProfile loggedInUser = userRepo.findByUsername(loggedInUsername);
        SecurityQuestionStatus sqStatus = sqRepo.findByUserId(loggedInUser.getId());
        if (sqStatus == null) {
            sqStatus = new SecurityQuestionStatus();
        }
        if (securityQuesRequest.getIsUsingSQ().equals(false)) {
            sqStatus.setQuestion(null);
            sqStatus.setAnswer(null);
            sqStatus.setIsUsingSQ(false);
            sqStatus.setUserId(loggedInUser.getId());
            sqRepo.save(sqStatus);
            baseResponse.setMessage("Successfully removed security question details.");
            baseResponse.setSuccess(true);
            return baseResponse;
        }
        if (securityQuestionsRepository.findAll().get(0).getQuestions()
                .contains(securityQuesRequest.getQuestion().toLowerCase())) {
            sqStatus.setUserId(loggedInUser.getId());
            sqStatus.setIsUsingSQ(true);
            sqStatus.setQuestion(securityQuesRequest.getQuestion().toLowerCase());
            sqStatus.setAnswer(bcryptEncoder.encode(securityQuesRequest.getAnswer().toLowerCase()));
            sqRepo.save(sqStatus);
            baseResponse.setMessage("Successfully added security question details.");
            baseResponse.setSuccess(true);
            return baseResponse;
        }
        baseResponse.setMessage("This question is not valid!");
        baseResponse.setSuccess(false);
        return baseResponse;
    }

    @Override
    public BaseResponse getSecurityQuestion(String username) {
        UserProfile user = userRepo.findByUsername(username);
        SecurityQuestionStatus sqStatus = sqRepo.findByUserId(user.getId());
        BaseResponse baseResponse = new BaseResponse();
        if (sqStatus != null && sqStatus.getQuestion() != null) {
            baseResponse.setMessage("Question returned.");
            baseResponse.setSuccess(true);
            baseResponse.setPayload(sqStatus.getQuestion());
            return baseResponse;
        }
        baseResponse.setMessage("Security question does not exist for this user!");
        baseResponse.setSuccess(false);
        return baseResponse;
    }

    @Override
    public BaseResponse getSecurityQuestions() {
        BaseResponse baseResponse = new BaseResponse();
        SecurityQuestionsResponse securityQuestionsResponse = new SecurityQuestionsResponse();
        int index = 0;
        List<String> questions = securityQuestionsRepository.findAll().get(0).getQuestions();

        if (questions != null && !questions.isEmpty()) {
            securityQuestionsResponse.setQuestion1(questions.get(index++));
            securityQuestionsResponse.setQuestion2(questions.get(index++));
            securityQuestionsResponse.setQuestion3(questions.get(index++));
            securityQuestionsResponse.setQuestion4(questions.get(index++));
            securityQuestionsResponse.setQuestion5(questions.get(index));
            baseResponse.setPayload(securityQuestionsResponse);
            baseResponse.setMessage("Security Questions returned.");
            baseResponse.setSuccess(true);
            return baseResponse;

        }
        baseResponse.setMessage("No question found!");
        baseResponse.setSuccess(false);
        return baseResponse;
    }

    @Override
    public BaseResponse checkSecurityQuestion(String username, SecurityQuesRequest securityQuesRequest) {
        UserProfile user = userRepo.findByUsername(username);
        SecurityQuestionStatus sqStatus = sqRepo.findByUserId(user.getId());
        AuthResponse authResponse = new AuthResponse();
        String hashedAns = sqStatus.getAnswer();
        String plainAns = securityQuesRequest.getAnswer();
        BaseResponse baseResponse = new BaseResponse();
        UserIdDetails userIdDetails = new UserIdDetails();
        BasicTextEncryptor encryptor = new BasicTextEncryptor();
        encryptor.setPassword(encryptorPassword);
        if (sqStatus.getQuestion() != null) {

            if (!BCrypt.checkpw(plainAns.toLowerCase(), hashedAns)) {
                baseResponse.setMessage("Answer is null or invalid");
                baseResponse.setSuccess(false);
                return baseResponse;
            }

            UserProfile userProfile = loadUserProfileByUsername(user.getUsername());
            invalidateExistingRefreshToken(user.getUsername());

            UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(userProfile.getId());
            if (userOrgRole != null)
                userRoleService.setUserIdDetails(userProfile, userIdDetails);
            else {
                authResponse.setReason(AuthenticationFailureConstants.LOGOUT);
                baseResponse.setMessage(ROLE_NOT_ASSIGNED_EXCEPTION.label);
                baseResponse.setSuccess(false);
                return baseResponse;
            }
            String jwtToken = requestUtil.jwtToken(userIdDetails, TokenConstants.ACCESS);
            String refreshToken = requestUtil.jwtToken(userIdDetails, TokenConstants.REFRESH);

            String hashedRefreshToken = userService.saveRefreshToken(refreshToken, user.getUsername());
            String encryptedJwtToken = encryptor.encrypt(jwtToken);

            authResponse.setToken(encryptedJwtToken);
            authResponse.setRefreshToken(hashedRefreshToken);

            authResponse.setAlbaUser(userProfile.getFirstName() + " " + userProfile.getLastName());
            authResponse.setUsername(userProfile.getUsername());
            baseResponse.setMessage(VALID_TOKEN_GENERATED.label);
            baseResponse.setSuccess(true);
            baseResponse.setPayload(authResponse);
            return baseResponse;

        }

        return baseResponse;
    }

    @Override
    public BaseResponse riskLevelCheck(UserProfile userProfile, FetchResponse fetchResponse) {
        BaseResponse riskCheckResponse = new BaseResponse();
        ResetPasswordResponse resetPasswordResponse = new ResetPasswordResponse();
        try {
            String userId = userProfile.getId();
            if (userId != null) {
                ResponseEntity<RiskResponse> riskScoreResponse = requestUtil.getRiskScore(userId, fetchResponse);
                RiskResponse riskResponse = riskScoreResponse.getBody();
                if (riskResponse != null) {
                    String riskLevel = riskResponse.getRiskLevel();
                    switch (riskLevel) {
                        case RBAConstants.HIGH_RISK -> {
                            riskCheckResponse.setMessage("User Access is forbidden because of high risk");
                            riskCheckResponse.setSuccess(false);
                            riskCheckResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.FORBIDDEN));
                            return riskCheckResponse;
                        }
                        case RBAConstants.MODERATE_RISK -> {
                            // second level of authentication
                            int passcode = generateOtp();
                            SimpleDateFormat sdf = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss zzz");
                            Date c = new Date(System.currentTimeMillis() + TokenConstants.OTP_TOKEN_DURATION);
                            String date = sdf.format(c);
                            String passcodeWithDate = passcode + "-" + date;
                            resetPasswordResponse.setPasscode(passcodeWithDate);
                            userService.addPasscode(userProfile.getEmailId(), passcodeWithDate);
                            String fetchResponseToken = requestUtil.getFetchResponseToken(userProfile.getEmailId(), fetchResponse);
                            emailUtil.sendOtpEmail(userProfile, passcode);
                            riskCheckResponse.setPayload(fetchResponseToken);
                            riskCheckResponse.setSuccess(false);
                            riskCheckResponse.setMessage("The user is required to go for OTP Verification.");
                            return riskCheckResponse;
                        }
                        case RBAConstants.LOW_RISK -> {
                            if (Boolean.TRUE.equals(riskResponse.getSuccess())) {
                                riskCheckResponse.setSuccess(true);
                            } else {
                                riskCheckResponse.setSuccess(false);
                                riskCheckResponse.setMessage("User can't Login because this IP is blocked!");
                            }
                            return riskCheckResponse;
                        }
                        default -> {
                            riskCheckResponse.setMessage("Error occured while calculating risk level");
                            riskCheckResponse.setSuccess(false);
                            riskCheckResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
                            return riskCheckResponse;
                        }
                    }
                }
            }
            riskCheckResponse.setMessage("Error occured while fetching username.");
            riskCheckResponse.setSuccess(false);
            riskCheckResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
            return riskCheckResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, AUTH_SERVICE_IMPL_CLASS, "riskLevelCheck", e.getMessage(), e.getStackTrace());
            riskCheckResponse.setMessage("Error occurred while calculating risk level");
            riskCheckResponse.setSuccess(false);
            return riskCheckResponse;
        }
    }

    @Override
    public Boolean saveAuthHistory(String userId, FetchResponse fetchResponse) {
        try {
            if (userId != null) {
                ResponseEntity<BaseResponse> saveHistoryResponse = requestUtil.saveAuthHistory(userId, fetchResponse);
                BaseResponse response = saveHistoryResponse.getBody();
                if (response != null) {
                    return response.getSuccess();
                }
            }
            return false;
        } catch (Exception e) {
            LOGGER.warn(AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG, AUTH_SERVICE_IMPL_CLASS, "saveAuthHistory", e.getMessage(), e.getStackTrace());
            return false;
        }
    }

    @Override
    public BaseResponse securityChecks(String username, FetchResponse fetchResponse) {
        BaseResponse baseResponse = new BaseResponse();
        AuthResponse authResponse = new AuthResponse();
        UserIdDetails userIdDetails = new UserIdDetails();
        try {
            UserProfile userProfile = loadUserProfileByUsername(username);
            if (userProfile != null) {
                AccountStatus accStatus = accStatusRepo.findByUserId(userProfile.getId());
                MfaStatus mfaStatus = mfaRepo.findByUserId(userProfile.getId());
                SecurityQuestionStatus sqStatus = sqRepo.findByUserId(userProfile.getId());
                String getUserAccountStatus = HelperUtil.getUserAccountStatus(accStatus);

                if (!Objects.equals(getUserAccountStatus, AuthConstants.ACCOUNT_ACTIVE)) {
                    incrementFailedAttempts(userProfile.getId(), fetchResponse);
                    baseResponse.setSuccess(false);
                    baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.FORBIDDEN));
                    baseResponse.setMessage(getUserAccountStatus);
                    return baseResponse;
                }

                // check for 2FA
                if (mfaStatus != null && mfaStatus.getIsEnabled() != null && Boolean.TRUE.equals(mfaStatus.getIsEnabled())) {
                    baseResponse.setMessage("The user is required to go for OTP Verification.");
                    authResponse.setIs2faEnabled(true);
                    String otpToken = requestUtil.verificationToken(userProfile.getEmailId(), TokenConstants.OTP_TOKEN_DURATION);

                    String fetchResponseToken = requestUtil.getFetchResponseToken(userProfile.getEmailId(), fetchResponse);

                    BasicTextEncryptor encryptor = new BasicTextEncryptor();
                    encryptor.setPassword(encryptorPassword);
                    String encryptedOtpToken = encryptor.encrypt(otpToken);

                    authResponse.setOtpToken(encryptedOtpToken);
                    authResponse.setFetchResponseToken(fetchResponseToken);
                    authResponse.setAlbaUser(userProfile.getFirstName() + " " + userProfile.getLastName());
                    authResponse.setReason(AuthenticationFailureConstants.MFA);
                    baseResponse.setSuccess(false);
                    baseResponse.setPayload(authResponse);
                    return baseResponse;
                }

                // check for Security Question
                if (Boolean.TRUE.equals(sqStatus != null && sqStatus.getIsUsingSQ() != null && sqStatus.getIsUsingSQ()) && sqStatus.getQuestion() != null) {
                    baseResponse.setMessage("The user is required to go for Security Question Verification.");
                    SecurityQuesRequest securityQuesRequest = new SecurityQuesRequest();
                    securityQuesRequest.setIsUsingSQ(true);
                    securityQuesRequest.setQuestion(sqStatus.getQuestion());
                    securityQuesRequest.setReason(AuthenticationFailureConstants.SQ);
                    baseResponse.setPayload(securityQuesRequest);
                    baseResponse.setSuccess(false);
                    LOGGER.info("Time taken by AuthController::createAuthenticationToken ");
                    return baseResponse;
                }

                // USER ROLE AND PERMISSIONS
                UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(userProfile.getId());
                if (userOrgRole != null) {
                    userRoleService.setUserIdDetails(userProfile, userIdDetails);
                    baseResponse.setPayload(userIdDetails);
                    baseResponse.setSuccess(true);
                    return baseResponse;
                } else {
                    incrementFailedAttempts(userProfile.getId(), fetchResponse);
                    authResponse.setReason(AuthenticationFailureConstants.LOGOUT);
                    baseResponse.setMessage(ROLE_NOT_ASSIGNED_EXCEPTION.label);
                    baseResponse.setSuccess(false);
                    return baseResponse;
                }
            }
            baseResponse.setMessage("User doesn't exist.");
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, AUTH_SERVICE_IMPL_CLASS, "securityChecks", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage("Exception Occured while validating authentication token!");
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
            return baseResponse;
        }
    }

    public int generateOtp() throws InvalidKeyException, NoSuchAlgorithmException {

        TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();
        Key key;
        final KeyGenerator keyGenerator = KeyGenerator.getInstance(totp.getAlgorithm());
        keyGenerator.init(160);
        key = keyGenerator.generateKey();
        final Instant now = Instant.now();
        return totp.generateOneTimePassword(key, now);
    }

    @Override
    public void blockDevice(String userId, FetchResponse fetchResponse) {
        requestUtil.blockDevice(userId, fetchResponse);
    }

    @Override
    public BaseResponse incrementFailedAttempts(String userId, FetchResponse fetchResponse) {

        BaseResponse baseResponse = new BaseResponse();
        UserSession userSession = userSessionRepo.findByUserId(userId);
        if (userSession == null) {
            userSession = new UserSession();
        }
        int failedAttempts = userSession.getFailedAttempts();
        if (failedAttempts == 6) {
            blockDevice(userId, fetchResponse);
        }
        if (failedAttempts >= 6) {
            baseResponse.setSuccess(false);
            baseResponse.setMessage("User can't Login because this IP is blocked");
            return baseResponse;
        }
        failedAttempts++;
        userSession.setUserId(userId);
        userSession.setFailedAttempts(failedAttempts);
        userSessionRepo.save(userSession);
        baseResponse.setSuccess(true);
        baseResponse.setMessage("");
        return baseResponse;
    }

    @Override
    public BaseResponse resetFailedAttempts(String userId) {
        BaseResponse baseResponse = new BaseResponse();
        UserSession userSession = userSessionRepo.findByUserId(userId);
        userSession.setFailedAttempts(0);
        userSessionRepo.save(userSession);
        baseResponse.setSuccess(true);
        return baseResponse;

    }

    @Override
    public BaseResponse authenticateOtpPasscode(HttpServletRequest httpServletRequest, String usermail, String passcode) {
        AuthResponse authResponse = new AuthResponse();
        String token = RequestUtil.extractRtFromRequest(httpServletRequest);
        BaseResponse checkPasscode = userService.checkPasscode(usermail, passcode);
        ResponseEntity<FetchResponse> fetchResponseEntity = rbaService.getFetchResFromToken(token);
        FetchResponse fetchResponse = fetchResponseEntity.getBody();
        UserProfile userProfile = loadUserProfileByMailId(usermail);

        if (Boolean.FALSE.equals((checkPasscode.getSuccess()))) {
            BaseResponse baseResponse = new BaseResponse();
            incrementFailedAttempts(userProfile.getId(), fetchResponse);
            authResponse.setReason(AuthenticationFailureConstants.INVALID_AUTH);
            baseResponse.setMessage("OTP has expired");
            baseResponse.setSuccess(false);
            baseResponse.setPayload(authResponse);
            return baseResponse;
        } else {
            userService.deleteChangeSecuritySettings(userProfile.getId());
            String username = userProfile.getUsername();
            ResponseEntity<BaseResponse> updateUserAuthHistoryResponseEntity = rbaService.updateAuthService(userProfile.getId(), fetchResponse);
            BaseResponse baseResponse = updateUserAuthHistoryResponseEntity.getBody();
            if (baseResponse != null && baseResponse.getSuccess().equals(true)) {
                baseResponse = securityChecks(username, fetchResponse);
                return baseResponse;
            }
        }
        BaseResponse baseResponse = new BaseResponse();
        authResponse.setReason(AuthenticationFailureConstants.RBA);
        baseResponse.setMessage("Action failed");
        baseResponse.setSuccess(false);
        baseResponse.setPayload(authResponse);
        return baseResponse;
    }

    @Override
    public BaseResponse checkForPassword(HttpServletRequest httpServletRequest, String password) {
        BaseResponse baseResponse = new BaseResponse();
        String token = requestUtil.extractJwtFromRequest(httpServletRequest);
        String username = requestUtil.usernameFromToken(token);
        UserProfile user = loadUserProfileByUsername(username);
        if (user == null) {
            baseResponse.setMessage("User does not exist.");
            baseResponse.setSuccess(false);
            return baseResponse;
        }

        String hashedPassword = user.getPassword();
        LOGGER.info(AUTHENTICATION_SERVICE_INFO_LOG_TAG, AUTH_SERVICE_IMPL_CLASS, "checkForPassword", "Info", "Checking for password");
        Boolean isAuthenticated = helperUtil.checkPass(password, hashedPassword);
        if (Boolean.TRUE.equals(isAuthenticated)) {
            baseResponse.setSuccess(true);
            LOGGER.info("Checking for password");
            baseResponse.setMessage("Authentication successful");
            return baseResponse;
        }
        baseResponse.setSuccess(false);
        baseResponse.setMessage("Wrong password. Please try again!");
        return baseResponse;
    }

    @Override
    public BaseResponse validateRefreshToken(String refreshToken) {
        BaseResponse baseResponse = new BaseResponse();
        Boolean isRefresh = RequestUtil.isRefreshToken(refreshToken);
        if (Boolean.TRUE.equals(isRefresh) && requestUtil.validateRefreshToken(refreshToken)) {
            baseResponse.setSuccess(true);
            baseResponse.setMessage("Refresh Token is valid!");
            return baseResponse;
        } else {
            throw new AuthServiceException(INVALID_REFRESH_TOKEN_EXCEPTION, HttpStatus.FORBIDDEN);
        }
    }

    @Override
    public BaseResponse generateNewAccessToken(HttpServletRequest httpServletRequest, String refreshToken, AuthRequest authenticationRequest) {
        BaseResponse baseResponse = new BaseResponse();
        AuthResponse authResponse = new AuthResponse();
        UserIdDetails userIdDetails = new UserIdDetails();
        Boolean isRefresh = RequestUtil.isRefreshToken(refreshToken);
        FetchResponse requestDetails = rbaService.fetchRequestDetails(httpServletRequest);
        if (Boolean.TRUE.equals(isRefresh) && requestUtil.validateRefreshToken(refreshToken)) {
            String decodedRefreshToken = requestUtil.getDecodedRefreshToken(refreshToken);
            String username = requestUtil.usernameFromToken(decodedRefreshToken);
            if (!username.equals(authenticationRequest.getUsername())) {
                baseResponse.setMessage("Refresh token does not match with the username");
                baseResponse.setSuccess(false);
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.FORBIDDEN));
                return baseResponse;
            }
            UserProfile userProfile = loadUserProfileByUsername(username);
            String hashedPassword = userProfile.getPassword();
            Boolean isPasswordValid = helperUtil.checkPass(authenticationRequest.getPassword(), hashedPassword);
            if (Boolean.FALSE.equals(isPasswordValid)) {
                baseResponse.setSuccess(false);
                baseResponse.setMessage("Invalid credentials");
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.FORBIDDEN));
                return baseResponse;
            }
            // USER ROLE AND PERMISSIONS
            UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(userProfile.getId());
            if (userOrgRole != null) {
                userRoleService.setUserIdDetails(userProfile, userIdDetails);
            } else {
                incrementFailedAttempts(userProfile.getId(), requestDetails);
                throw new AuthServiceException(ROLE_NOT_ASSIGNED_EXCEPTION, HttpStatus.FORBIDDEN);
            }

            // fetch and check for existence of all the roles and permissions
            UserIdDetails userRoleDetails = userRoleService.fetchUserIdDetails(userOrgRole, authenticationRequest, userProfile);

            String jwtToken = requestUtil.jwtToken(userIdDetails, TokenConstants.ACCESS);
            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            encryptor.setPassword(encryptorPassword);
            String encryptedJwtToken = encryptor.encrypt(jwtToken);

            String newRefreshToken = requestUtil.jwtToken(userIdDetails, TokenConstants.REFRESH);
            String hashedRefreshToken = userService.saveRefreshToken(newRefreshToken, username);

            return setAuthResponse(
                    baseResponse,
                    authResponse,
                    userProfile,
                    hashedRefreshToken,
                    encryptedJwtToken,
                    userRoleDetails
            );
        } else {
            throw new AuthServiceException(INVALID_REFRESH_TOKEN_EXCEPTION, HttpStatus.FORBIDDEN);
        }
    }

    private BaseResponse setAuthResponse(
            BaseResponse baseResponse,
            AuthResponse authResponse,
            UserProfile userProfile,
            String refreshToken,
            String encryptedJwtToken,
            UserIdDetails userRoleDetails
    ) {
        authResponse.setToken(encryptedJwtToken);
        authResponse.setRefreshToken(refreshToken);
        authResponse.setAlbaUser(userProfile.getFirstName() + " " + userProfile.getLastName());
        authResponse.setUsername(userProfile.getUsername());
        authResponse.setProfileImageDetails(userProfile.getProfileImageDetails());
        authResponse.setUserIdDetails(userRoleDetails);

        baseResponse.setMessage(VALID_TOKEN_GENERATED.label);
        baseResponse.setSuccess(true);
        baseResponse.setPayload(authResponse);

        return baseResponse;
    }
}
