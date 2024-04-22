package com.albanero.authservice.common.dto.request;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
public class VaultDetails {
	private String requestId;
	private String leaseId;
	private Boolean renewable;
	private String data;
	private String wrapNull;
	private String warnings;
	private Auth auth;
}
