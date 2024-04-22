package com.albanero.authservice.common.constants;

public enum CommonLoggingConstants {

    PERMISSION_NOT_FOUND("Permission not found with this permissionId "),
    ASSIGNED_PERMISSION_NOT_FOUND("The assigned permissions not found "),
    ORGANIZATION_NOT_FOUND("Organization not found with this organizationId "),
    ASSIGNED_ORGANIZATION_NOT_FOUND("The assigned Organization not found "),
    PROJECT_ORG_ROLE_NOT_FOUND("ProjectOrgRole not found with this projectOrgRoleId "),
    ASSIGNED_PROJECT_ORG_ROLE_NOT_FOUND("The assigned project role not found "),
    PROJECT_NOT_FOUND("Project not found with this projectId "),
    ASSIGNED_PROJECT_NOT_FOUND("The assigned project not found "),
    ROLE_NOT_FOUND("Role not found with this RoleId "),
    ASSIGNED_ROLE_NOT_FOUND("The assigned roles not found "),
    USERID("userId ");

    public final String label;

    CommonLoggingConstants(String label) {
        this.label = label;
    }

    @Override
    public String toString() {
        return this.label;
    }
}
