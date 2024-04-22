package com.albanero.authservice.common.dto.request;

import lombok.Data;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

@Data
public class ApiDetails {
	@NotBlank
	private String apiRoute;
	@NotBlank
	private String apiMethod;
	private String userId;
	@Valid
	private OrgLevelDetails orgDetails;
	private PlatformLevelRoleDetails platformDetails;
	@Valid
	private ProjectLevelDetails projectLevelDetails;
}
