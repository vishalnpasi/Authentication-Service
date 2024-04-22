package com.albanero.authservice.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Document(collection = "accountStatus")
@Schema(description = "The persistent class for User.")
public class AccountStatus {
	@Id
	private String id;
	@Indexed(unique = true)
	private String userId;
	private EmailStatus emailStatus;
	private AccountApprovalStatus accountApprovalStatus;
	private AccountActivationStatus accountActivationStatus;
	private Boolean unblockRequested;
}
