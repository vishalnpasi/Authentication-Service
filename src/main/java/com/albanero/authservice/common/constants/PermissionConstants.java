package com.albanero.authservice.common.constants;


/**
 *
 */
public final class PermissionConstants {

    public static final String ORG_WATCHER = "Organization Watcher";

    public static final String PROJECT_DEFAULT = "project-default";

    public static final String ORGANIZATION_DEFAULT = "organization-default";

    public static final String ORG_ADMIN = "Organization Admin";

    public static final String PROJECT_ADMIN = "Project Admin";

    public static final String ROOT_USER = "root-user";

    public static final String DATA_ENGINEER = "Data Engineer";

    public static final String DATA_OPERATIONS = "Data Operations Lead";

    public static final String DATA_GOVERNANCE_LEAD = "Data Governance Lead";

    public static final String DATA_STEWARD = "Data Steward";

    public static final String BUSINESS_STEWARD = "Business Steward";

    public static final String M3_OPERATIONS_LEAD = "M3 Operations Lead";

    private static final String[] API_METHODS = new String[]{"PUT", "GET", "DELETE", "POST", "PATCH"};
    public static String[] validApiMethods() {
        return API_METHODS;
    }
    public static final String PROJECT = "project";
    public static final String PROJECT_CUSTOM = "project-custom";
    public static final String ORGANIZATION_CUSTOM = "organization-custom";
    public static final String DEFAULT_MODULE = "Default";
    public static final String USER_DEFAULT = "User Default";
    public static final String USER_SETTINGS = "User Settings";
    private PermissionConstants() {
        throw new IllegalStateException("PermissionConstants class");
    }
}
