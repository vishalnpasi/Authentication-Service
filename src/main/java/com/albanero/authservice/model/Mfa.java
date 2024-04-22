package com.albanero.authservice.model;

import org.springframework.data.mongodb.core.mapping.Document;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Document(collection = "mfaStatus")
@Schema(description = "The persistent class for Google MFA Auth Details.")
public class Mfa {
	private String providerApp;
	private String mfaSecret;
}
