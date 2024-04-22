package com.albanero.authservice.common.dto.response;

import java.util.List;

import com.albanero.authservice.common.dto.request.OrgLevelDetails;
import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RolePermissionDetails {
	String role;
	String roleId;
	List<String> rolePermissions;
	List<ModuleNameDto> permissionTree;
	List<OrgLevelDetails> organizationDetails;
	String roleDescription;
}
