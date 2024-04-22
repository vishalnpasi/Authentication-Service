package com.albanero.authservice.common.dto.request;

import java.util.List;

import com.albanero.authservice.common.dto.response.RolePermissionDetails;
import com.fasterxml.jackson.annotation.JsonInclude;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Request DTO class for organization roles and their corresponding permissions")
public class OrgRolePermissions {
	String orgId;
	String orgName;
	List<RolePermissionDetails> rolePermissions;
}
