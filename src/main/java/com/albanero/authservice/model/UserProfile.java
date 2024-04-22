package com.albanero.authservice.model;

import java.util.Date;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.format.annotation.DateTimeFormat;

import com.albanero.authservice.common.dto.response.ProfileImageDetails;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * The persistent class for User.
 * 
 * @author arunima.mishra
 */
@Data
@Document(collection = "userProfile")
@Schema(description = "The persistent class for User.")
public class UserProfile {

	@Id
	private String id;
	@Indexed
	private String username;
	private String emailId;
	private String password;
	private String role;
	private String firstName;
	private String lastName;
	private ProfileImageDetails profileImageDetails;
	@DateTimeFormat(style = "M-") 
	@CreatedDate
	private Date created;
	@LastModifiedDate
	private Date updated;

	
}




