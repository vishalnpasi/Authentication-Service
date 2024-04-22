package com.albanero.authservice.common.constants;

/**
 * Class that provide PathVariable mapping constants
 */
public final class PathVariables {
    public static final String ID_PARAM = "/{" + RequestParams.ID + "}";
    public static final String TOKEN_PARAM = "/{" + RequestParams.TOKEN + "}";
    public static final String REFRESH_TOKEN_PARAM = "/{" + RequestParams.REFRESH_TOKEN + "}";
    public static final String USERNAME_PARAM = "{" + RequestParams.USERNAME + "}";
    public static final String USERNAME_PARAM2 = "/{" + RequestParams.USERNAME + "}";
    public static final String MAIL_ID_PARAM = "/{" + RequestParams.MAIL_ID + "}";
    public static final String PASSCODE_PARAM = "/{" + RequestParams.PASSCODE + "}";
    public static final String USES_2FA_PARAM = "/{" + RequestParams.USES_2FA + "}";
    public static final String USERNAME_PARAM1 = "/{" + RequestParams.USERNAME + "}";
    public static final String PASSWORD_PARAM = "/{" + RequestParams.PASSWORD + "}";
    public static final String CONFIRMED_PASSWORD_PARAM = "/{" + RequestParams.CONFIRMED_PASSWORD + "}";
    public static final String OLD_PASSWORD_PARAM = "/{" + RequestParams.OLD_PASSWORD + "}";
    public static final String ORG_NAME_PARAM = "/{" + RequestParams.ORG_NAME + "}";
    public static final String USER_ID_PARAM = "/{" + RequestParams.USER_ID + "}";
    public static final String PROJECT_ORG_ROLE_ID_PARAM = "/{" + RequestParams.PROJECT_ORG_ROLE_ID + "}";
    public static final String HASHED_TOKEN = "/{" + RequestParams.HASHED_TOKEN + "}";
    public static final String ORG_ID_PARAM = "/{" + RequestParams.ORG_ID + "}";
    public static final String PROJECT_ID_PARAM = "/{" + RequestParams.PROJECT_ID + "}";
    public static final String CHECK_PASSWORD_PARAM = "/{" + RequestParams.CHECK_PASSWORD + "}";
    public static final String ROLE_ID = "/{" + RequestParams.ROLE_ID + "}";
    public static final String PERMISSION_MODULE_ID = "/{" + RequestParams.PERMISSION_MODULE_ID + "}";

    private PathVariables() {
        throw new IllegalStateException("PathVariables class");
    }
}
