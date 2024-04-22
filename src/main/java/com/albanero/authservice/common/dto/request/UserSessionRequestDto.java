package com.albanero.authservice.common.dto.request;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;


import java.util.Date;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserSessionRequestDto {
	private String id;
	private String userId;
	private String hashedRT;
	private String encryptedRT;
	private int failedAttempts;
	private Date created;
	private Date updated;
}
