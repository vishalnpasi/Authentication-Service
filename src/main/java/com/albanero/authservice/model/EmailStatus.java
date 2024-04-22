package com.albanero.authservice.model;

import org.springframework.data.mongodb.core.mapping.Document;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Document(collection = "accountStatus")
@Schema(description = "The persistent class for Google MFA Auth Details.")
public class EmailStatus {
	private Boolean isVerified;
	private String verificationCode;
}
