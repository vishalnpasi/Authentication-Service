package com.albanero.authservice.common.dto.request;





import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * Request DTO class for all Authentication REST API Calls
 */
@Data
@EqualsAndHashCode(callSuper=false)
@Schema(description = "Request DTO class for all Authentication REST API Calls")
public class RegistrationUser extends AuthRequest {
	private String confirmedPassword;
	private String mailId;
	private Boolean isUsing2FA;
	private String firstName;
	private String lastName;
	private String organization;
	private String givenName;
	private String familyName;
	private String name;
	private String secret;
	private String securityQuestion;
	private String securityAnswer;
	private String profileImage;
	private String orgUrl;
	private Boolean isResetMfaRequest;
	private String userCode;
	private String ip;
}
