package com.albanero.authservice.common.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

/**
 * Base Response DTO class for all REST API Calls
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
public class RiskResponse {

	String message;
	Boolean success;
	String riskLevel;
	
}
