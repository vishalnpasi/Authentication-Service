package com.albanero.authservice.common.dto.request;

import com.albanero.authservice.common.constants.AuthenticationFailureConstants;
import com.fasterxml.jackson.annotation.JsonInclude;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Data;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
@Schema(description = "Security Question Request DTO class for Security Question API Calls")
public class SecurityQuesRequest {
	
	@Schema(description = "Security Question")
	String question;
	@Schema(description = "Security Answer")
	String answer;
	@Schema(description = "Is user using Security Question")
	Boolean isUsingSQ;
	private AuthenticationFailureConstants reason;

}
