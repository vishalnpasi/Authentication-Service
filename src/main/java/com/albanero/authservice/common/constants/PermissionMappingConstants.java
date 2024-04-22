package com.albanero.authservice.common.constants;

public final class PermissionMappingConstants {


    public static final String FEED_ENDPOINT = "/api-endpoint";
    public static final String GET_ROLE_PERMISSIONS = "/role-permissions";

    public static final String GET_ROLES = "/roles";
    public static final String GET_PERMISSIONS = "/permissions";
    public static final String USER_ROLES = "/user-roles";
    public static final String PERMISSION_TREE = "/permission-tree";
    public static final String PERMISSION_MODULES = "/permission-modules";
    public static final String DETACH_PERMISSION_FROM_ROLE = "/detach-permission-from-role";
    public static final String DETACH_API_FROM_PERMISSION = "/detach-api-from-permission";
    public static final String REMOVE_OR_UPDATE_API_FROM_ALL_PERMISSIONS = "/remove-or-update-api-from-all-permissions";
    public static final String UPDATE_SUBDOMAIN = "/permission-sub-module";
    public static final String SUBMODULE = "/sub-module";
    public static final String MODULE = "/module";
    public static final String PLATFORM_API_DETAILS = "/platform-api-details";

    private PermissionMappingConstants() {
        throw new IllegalStateException("PermissionMappingConstants class");

    }

}
