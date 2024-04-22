package com.albanero.authservice.common.constants;

/**
 * Interface that provide RestController mapping constants for
 *
 */
public final class OrgConstants {
	public static final String ORG_DETAILS = "/user/organization";
	public static final String USER_ORG = "/user/organization";
	public static final String ORG_MEMBER = "/user/organization/member";
	public static final String VERIFY_ORG = "/verify-org";
	public static final String ORG_ROLE_PERMISSIONS = "/user/organization/role-permissions";
	public static final String DEFAULT_ROLES = "/user/organization/default-roles";
	public static final String ORG_PRODUCTS = "/user/organization/products" + PathVariables.ORG_ID_PARAM;
	public static final String USERS_IN_ORG = "/organization/users";
	public static final String UNAPPROVED_USERS_IN_ORG = "/organization/unapproved-users";
	public static final String USER_ORG_ROLES = "/user/org-roles";
	private OrgConstants() {
		throw new IllegalStateException("OrgConstants class");
	}
}
