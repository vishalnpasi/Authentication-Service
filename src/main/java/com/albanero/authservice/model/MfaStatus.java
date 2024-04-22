package com.albanero.authservice.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Document(collection = "mfaStatus")
@Schema(description = "The persistent class for User.")
public class MfaStatus {
	@Id
	private String id;
	@Indexed(unique = true)
	private String userId;
	private Boolean isEnabled;
	private Mfa mfa;
}
