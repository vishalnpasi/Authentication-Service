package com.albanero.authservice.common.dto.request;

import java.util.List;

import com.albanero.authservice.common.dto.response.ModuleNameDto;
import com.albanero.authservice.common.dto.response.RolePermissionDetails;
import com.albanero.authservice.model.Product;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class UserIdDetails {
	private UserProfileDetails userProfileDetails;
	private List<OrgLevelDetails> orgLevelDetails;
	private List<RolePermissionDetails> platformRoleDetails;
	private List<Product> productDetails;
	private List<ProjectLevelDetails> projectLevelDetails;
	private List<ModuleNameDto> userPermissionTree;
	private CurrentContext currentContext;
}
