package com.albanero.authservice.common.dto.request;

import java.util.List;

import lombok.Data;

@Data
public class Auth {
	private String clientToken;
	private String accessor;
	private List<String> policies;
	private List<String> tokenPolicies;
	private Metadata metadata;
	private Integer leaseDuration;
	private Boolean renewable;
	private String entityId;
	private String tokenType;
	private Boolean orphan;
}
