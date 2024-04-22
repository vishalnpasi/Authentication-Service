package com.albanero.authservice.common.constants;

public final class UserConstants {
    public static final String USER = "/user";
    public static final String GOOGLE_AUTH_USER = "/user/google-auth";
    public static final String ADD_PASSCODE = "/user/passcode" + PathVariables.MAIL_ID_PARAM;
    public static final String CHECK_PASSCODE = "/user/passcode-link" + PathVariables.MAIL_ID_PARAM + PathVariables.PASSCODE_PARAM;
    public static final String ADD_PASSWORD = "/user/reset-password" + PathVariables.MAIL_ID_PARAM + PathVariables.PASSWORD_PARAM;
    public static final String VALIDATE_USER = "/user/validate/" + PathVariables.USERNAME_PARAM;
    public static final String UPDATE_MFA = "/user/Mfa";

    private UserConstants() {
        throw new IllegalStateException("UserConstants class");
    }

}
