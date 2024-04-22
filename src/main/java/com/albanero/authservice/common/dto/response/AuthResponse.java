package com.albanero.authservice.common.dto.response;

import java.util.List;


import com.albanero.authservice.common.constants.AuthenticationFailureConstants;
import com.albanero.authservice.common.dto.request.OrgLevelDetails;
import com.albanero.authservice.common.dto.request.ProjectLevelDetails;
import com.albanero.authservice.common.dto.request.UserIdDetails;
import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * Response DTO class for all Authentication REST API Calls
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
@EqualsAndHashCode(callSuper=false)
public class AuthResponse extends BaseResponse {
	private String token;
	private String refreshToken;
	private Boolean is2faEnabled;
	private String otpToken;
	private String albaUser;
	private String organizationName;
	private String accessLevel;
	private List<ProductRoles> productRolesList;
	private String userPermissions;
	private String username;
	private String userMail;
	private AuthenticationFailureConstants reason;
	private List<OrgLevelDetails> orgLevelDetails;
	private List<RolePermissionDetails> platformRoleDetails;
	private List<ProjectLevelDetails> projectLevelDetails;
	private ProfileImageDetails profileImageDetails;
	private String fetchResponseToken;
	private UserIdDetails userIdDetails;

}
