package com.albanero.authservice.common.constants;

public final class UserMappingConstants {


    public static final String USER = "/user";
    public static final String SAVER_TOKEN = "/save/refreshtoken";
    public static final String USERMAIL = "/usermail";
    public static final String USER_PROFILE = "/user/profile";
    public static final String USER_PROFILE_DETAILS = "/user-profile";
    public static final String REGISTER_USER = "/reg-alba-user";
    public static final String GOOGLE_AUTH_USER = "/user/google-auth/";
    public static final String ADD_PASSCODE = "/user/passcode" + PathVariables.MAIL_ID_PARAM;
    public static final String CHECK_PASSCODE = "/user/passcode-link" + PathVariables.MAIL_ID_PARAM + PathVariables.PASSCODE_PARAM;
    public static final String ADD_PASSWORD = "/user/reset-password";
    public static final String VALIDATE_USER = "/user/validate/" + PathVariables.USERNAME_PARAM;
    public static final String UPDATE_MFA = "/user/mfa";
    public static final String VERIFY_USERNAME = "/verify-username" + PathVariables.USERNAME_PARAM1;
    public static final String VERIFY_EMAIL = "/verify-email" + PathVariables.MAIL_ID_PARAM;
    public static final String CHANGE_PASSWORD = "/user/change-password/";
    public static final String VERIFY_USER_ACCESS = "/user/verify-access";
    public static final String FETCH_USERNAME = "/user/username" + PathVariables.USER_ID_PARAM;
    public static final String PRODUCT_MEMBER = "/user/product";
    public static final String PRODUCT_DETAILS = "/user/product";
    public static final String USER_DETAILS = "/user-details";
    public static final String FETCH_EMAIL = "/user/email";
    public static final String VERIFY_USER = "/user/verify/email";
    public static final String REQUEST_USER_APPROVAL = "/user/approve";
    public static final String APPROVE_USER = "/user/approve-account";
    public static final String RESEND_VERIFICATION_LINK = "/user/resend-verification-link";
    public static final String GENERATE_MFA_QR_AND_SECRET = "/user/mfa-qr";
    public static final String PROFILE_IMAGE = "/profile-image";
    public static final String FETCH_USER_MAPPINGS = "/user-mappings";
    public static final String VERIFY_ORG = "/verify-org";
    public static final String CHECK_PASSWORD = "/user/check-password";
    public static final String ADD_SQ = "/user/reset-SQ";
    public static final String DELETE_SECURITY_SETTINGS = "/delete-security-settings";
    public static final String USERS = "/users";
    public static final String CHANGE_USERS_ACCOUNT_STATUS = "/users/account-status";
    public static final String REQUEST_UNBLOCK = "/users/request-unblock";
    public static final String UNBLOCK_USER = "/users/unblock";
    public static final String FETCH_USERNAME_FROM_TOKEN = "/token/username";
    public static final String USER_ROLE = "/user-profile-role";
    public static final String SET_DEFAULT_PROJECT_ROLE = "/set-default-role";

    private UserMappingConstants() {
        throw new IllegalStateException("UserMappingConstants class");

    }


}
