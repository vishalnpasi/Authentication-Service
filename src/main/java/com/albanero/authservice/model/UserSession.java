package com.albanero.authservice.model;

import java.util.Date;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.format.annotation.DateTimeFormat;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Document(collection = "userSession")
@Schema(description = "The persistent class for User.")
public class UserSession {
	@Id
	private String id;
	@Indexed
	private String userId;
	private String hashedRT;
	private String encryptedRT;
	private int failedAttempts;
	@DateTimeFormat(style = "M-") 
	@CreatedDate
	private Date created;
	@LastModifiedDate
	private Date updated;
}
