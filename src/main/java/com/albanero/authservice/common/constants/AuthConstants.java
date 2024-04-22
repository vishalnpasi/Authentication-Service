package com.albanero.authservice.common.constants;

import com.albanero.authservice.controller.AuthController;

/**
 * Class that provide RestController mapping constants for
 * {@link AuthController}
 */
public final class AuthConstants {
    // AuthController
    public static final String AUTHENTICATE = "/authenticate";
    public static final String USERNAME = "/auth-token/api/username/";
    public static final String GENERATE_TOKEN = "/auth-token/api/generate-token/";
    public static final String VERIFY_MFA = "/mfa/verify";
    public static final String VERIFY_FROM_MFA_SERVICE = "/mfa/api/verify";
    public static final String VALIDATE_ACCESS_TOKEN = "/token/validate";
    public static final String VALIDATE_TOKEN = VALIDATE_ACCESS_TOKEN + PathVariables.TOKEN_PARAM;
    public static final String VALIDATE_TOKEN_FROM_TOKEN_SERVICE = "/auth-token/api/validate/";
    public static final String VALIDATE_REFRESH_TOKEN = "/refresh-token/validate" + PathVariables.REFRESH_TOKEN_PARAM;
    public static final String INVALIDATE_REFRESH_TOKEN = "/refresh-token/invalidate" + PathVariables.USERNAME_PARAM2;
    public static final String CHECK_FOR_MFA = "/mfa" + PathVariables.MAIL_ID_PARAM;
    public static final String GENERATE_MFA_SECRET = "/mfa/api/generate-secret";
    public static final String GET_ENCODED_TOKEN = "/auth-token/api/encoded-token/";
    public static final String GET_EXPIRATION_DATE = "/auth-token/api/expiration-date/";

    public static final String AUTHENTICATE_MFA = "/mfa/authenticate";

    public static final String CHECK_FOR_SQ = "/security-ques" + PathVariables.USERNAME_PARAM;
    public static final String CHECK_FOR_PASSWORD = "/check-password";
    public static final String LOGOUT = "/logout";
    public static final String CHECK_MFA = "/check-mfa";
    public static final String CHECK_SQ = "/check-SQ";
    public static final String GET_EMAIL_FROM_TOKEN = "/auth-token/api/email/";
    public static final String GENERATE_INTERNAL_TOKEN = "/internal-token";
    public static final String SECURITY_QUESTION = "/security-question";
    public static final String VALIDATE_SECURITY_QUESTION = "/validate/security-question";
    public static final String SECURITY_QUESTIONS = "/security-questions";
    public static final String USER_MAPPINGS = "/auth-token/api/user-mappings/";
    public static final String GET_MAPPINGS_FROM_TOKEN = "/auth-token/api/mappings/";
    public static final String SECURITY_CHECKS = "/security-checks";
    public static final String GENERATE_FETCH_RESPONSE_TOKEN = "/auth-token/api/fetch-response/";
    public static final String GET_FETCH_RESPONSE_FROM_TOKEN = "/auth-token/api/fetch-response/";
    public static final String INCREMENT_FAILED_ATTEMPTS = "/increment-failed-attempts";
    public static final String RESET_FAILED_ATTEMPTS = "/reset-failed-attempts";
    public static final String AUTHORIZE_API_ROUTES = "/authorize-route";
    public static final String GET_INTERNAL_TOKEN = "/auth-token/api/internal-token";
    public static final String ACCOUNT_UNVERIFIED = "This account is not verifed";
    public static final String ACCOUNT_UNAPPROVED = "This account is not approved";
    public static final String ACCOUNT_DEACTIVATED = "This account has been deactivated";
    public static final String ACCOUNT_ACTIVE = "This account is active";
    public static final String AUTHENTICATE_PASSCODE = "/authenticate/passcode";
    public static final String GENERATE_NEW_ACCESS_TOKEN = "/generate-new-access-token" + PathVariables.REFRESH_TOKEN_PARAM;

    private AuthConstants() {
        throw new IllegalStateException("AuthConstants class");
    }
}
