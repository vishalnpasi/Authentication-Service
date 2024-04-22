package com.albanero.authservice.common.constants;

/**
 * Interface that provide RestController mapping constants for
 * {@link UserController}
 */
public final class ProjectConstants {
    public static final String ORG_PROJECT = "/user/organization/project";
    public static final String ORG_PROJECT_DETAILS = ORG_PROJECT + PathVariables.ORG_ID_PARAM;
    public static final String PROJECT_MEMBER = "/user/organization/project/member";
    public static final String VERIFY_PROJECT = "/verify-project";
    public static final String PROJECT_ROLE_PERMISSIONS = "/user/organization/project/role-permissions";
    public static final String DEFAULT_ROLES = "/user/organization/project/default-roles";
    public static final String USERS_IN_PROJECT = "/organization/project/users";
    public static final String USER_PROJECTS = "/user/projects";
    public static final String USER_PROJECT_ROLES = "/user/project-roles";
    public static final String USER_DEFAULT_PROJECT = "/user/default-project";
    public static final String USER_REMOVE_DEFAULT_PROJECT = "/user/remove-default-project";
    public static final String USER_DEFAULT_PROJECT_ROLE = "/user/default-project-role";

    private ProjectConstants() {
        throw new IllegalStateException("Utility class");
    }
}
