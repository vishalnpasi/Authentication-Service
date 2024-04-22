package com.albanero.authservice.common.dto.response;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper=false)
public class RegisterUserResponse extends BaseResponse{
	private Boolean isMfaEnabled;
	private String secretQrImageUri;
	private String secret;
	private Boolean isEmailChanged;
	private String firstNameMessage;
	private String lastNameMessage;
	private String emailMessage;
	private String usernameMessage;
}
