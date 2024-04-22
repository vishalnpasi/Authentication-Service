package com.albanero.authservice.common.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Data;

@Data
@Schema(description = "Change Password Request DTO class for changing Password API Calls")
public class ChangePasswordRequest {
	
	@Schema(description = "Token required for authentication")
	private String token;
	@Schema(description = "Password which is already saved")
	private String oldPassword;
	@Schema(description = "Password which is to be saved")
	private String newPassword;
	@Schema(description = "Password same as new Password")
	private String confirmedPassword;
	@Schema(description = "MailId of the user")
	private String mailId;
	@Schema(description = "Passcode received on mail")
	private String passcode;
}
