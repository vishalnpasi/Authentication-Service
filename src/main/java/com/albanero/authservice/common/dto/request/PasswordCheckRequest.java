package com.albanero.authservice.common.dto.request;

import com.fasterxml.jackson.annotation.JsonInclude;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Request DTO class for password check")
public class PasswordCheckRequest {
	String currentPassword;
}
