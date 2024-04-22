package com.albanero.authservice.common.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ProjectOrgRoleId {
	private String projectOrganizationRoleId;
	private Boolean isDefault;
}