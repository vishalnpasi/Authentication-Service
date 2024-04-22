package com.albanero.authservice.common.dto.request;

import java.util.List;

import lombok.Data;

@Data
public class PlatformLevelRoleDetails {
	String role;
	String roleId;
	List<String> rolePermissions;
}
