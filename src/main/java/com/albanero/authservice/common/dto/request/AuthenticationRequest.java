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
public class AuthenticationRequest {

	private String emailId;

}
