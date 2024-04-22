package com.albanero.authservice.common.dto.request;

import com.albanero.authservice.common.dto.response.RolePermissionDetails;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import jakarta.validation.constraints.NotBlank;
import java.util.List;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProjectLevelDetails {
	String projectOrgId;
	String orgId;
	String orgName;
	String projectName;
	@NotBlank
	String projectId;
	String newProjectName;
	String orgUrl;
	String projectUrl;
	List<RolePermissionDetails> userRoles;
	String role;
	String roleId;
	List<String> rolePermissions;
	String defaultRole;
	String defaultRoleId;
	Integer usersCount;
	Boolean isDefault;
}
