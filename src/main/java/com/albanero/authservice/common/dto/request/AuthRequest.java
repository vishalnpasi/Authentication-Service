package com.albanero.authservice.common.dto.request;

import com.fasterxml.jackson.annotation.JsonInclude;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * Request DTO class for all Authentication REST API Calls
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Request DTO class for all Authentication REST API Calls")
public class AuthRequest {

	private String username;
	private String emailId;
	private String password;
	private String verificationCode;
	private String otpToken;
	private Boolean uses2FA;
	private String mfaSecret;

	private String token;
	private String fetchResponseToken;
	private OrgLevelDetails orgDetails;
	private PlatformLevelRoleDetails platformDetails;
	private ProjectLevelDetails projectLevelDetails;
}
