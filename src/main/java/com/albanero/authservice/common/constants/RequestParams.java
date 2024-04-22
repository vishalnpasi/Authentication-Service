package com.albanero.authservice.common.constants;

/**
 * Class that provides RequestParam mapping constants
 *
 */
public final class RequestParams {
    public static final String ID = "id";
    public static final String TOKEN = "token";
    public static final String REFRESH_TOKEN = "refreshToken";
    public static final String STATUS = "status";
    public static final String USERNAME = "username";
    public static final String MAIL_ID = "usermail";
    public static final String PASSCODE = "passcode";
    public static final String PASSWORD = "newPassword";
    public static final String USES_2FA = "uses2FA";
    public static final String OLD_PASSWORD = "oldPassword";
    public static final String ORG_NAME = "orgName";
    public static final String USER_ID = "userId";
    public static final String PROJECT_ORG_ROLE_ID = "projectOrgRoleId";
    public static final String SECURITY_QUESTION = "question";
    public static final String SECURITY_ANSWER = "answer";
    public static final String HASHED_TOKEN = "hashed-token";
    public static final String IMAGE = "image";
    public static final String CURRENT_PASSWORD = "currentPassword";
    public static final String ORG_ID = "orgId";
    public static final String PROJECT_ID = "projectId";
    public static final String CHECK_PASSWORD = "password";
    public static final String ROLE_ID = "roleId";
    public static final String PERMISSION_MODULE_ID = "permissionModuleId";
    public static final String PERMISSION_MODULE_NAME = "permissionModuleName";
    public static final String CONFIRMED_PASSWORD = "confirmedPassword";
    private RequestParams() {
        throw new IllegalStateException("RequestParams class");
    }
}
