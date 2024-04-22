package com.albanero.authservice.common.dto.request;


import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class ChangeSQRequest {

	@Schema(description = "Token required for authentication")
	private String token;
	@Schema(description = "Security Question")
	private String question;
	@Schema(description = "Security Answer")
	private String answer;
	@Schema(description = "MailId of the user")
	private String mailId;
	@Schema(description = "Passcode received on mail")
	private String passcode;
}
