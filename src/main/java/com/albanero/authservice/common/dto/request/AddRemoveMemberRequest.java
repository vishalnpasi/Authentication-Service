package com.albanero.authservice.common.dto.request;


import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Data;

@Data
@Schema(description = "Add Member Request DTO class for org member API Calls")
public class AddRemoveMemberRequest {
	@Schema(description = "Email of org member")
	String email;
	@Schema(description = "Role of org member")
	String role;
	@Schema(description = "Organisation Id of org member")
	String orgId;
	@Schema(description = "Organisation Name of org member")
	String orgName;
	@Schema(description = "Organisation URL of org member")
	String orgUrl;
	@Schema(description = "Project Name")
	String projectName;
	@Schema(description = "Project URL")
	String projectUrl;
	@Schema(description = "Project ID")
	String projectId;
}
