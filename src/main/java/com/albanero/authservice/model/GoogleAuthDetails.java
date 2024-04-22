package com.albanero.authservice.model;

import java.util.Date;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.mapping.Document;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * The persistent class for Google MFA Auth Details.
 * 
 * @author arunima.mishra
 */
@Data
@Document(collection = "DaoUser")
@Schema(description = "The persistent class for Google MFA Auth Details.")
public class GoogleAuthDetails {
	@Id
	private String id;
	private Boolean isUsing2FA;
    private String secret;
    @CreatedDate
	private Date created;
	@LastModifiedDate
	private Date updated;
}
