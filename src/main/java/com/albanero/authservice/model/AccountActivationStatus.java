package com.albanero.authservice.model;


import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

@Data
@Document(collection = "accountStatus")
@Schema(description = "The persistent class for Google MFA Auth Details.")
public class AccountActivationStatus {
	private Boolean isActive;
	private Date statusChangedAt;
	private String statusChangedBy;
}
