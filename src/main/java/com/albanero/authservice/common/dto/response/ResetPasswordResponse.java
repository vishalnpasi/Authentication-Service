package com.albanero.authservice.common.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;
import lombok.EqualsAndHashCode;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
@EqualsAndHashCode(callSuper=false)
public class ResetPasswordResponse extends BaseResponse{
	String passcode;
	Boolean isValidPasscode;
}
