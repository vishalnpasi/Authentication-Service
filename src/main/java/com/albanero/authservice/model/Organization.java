package com.albanero.authservice.model;

import java.util.Date;
import java.util.List;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.format.annotation.DateTimeFormat;

import lombok.Data;

@Data
@Document(collection = "organization")
public class Organization {
	@Id
	private String id;
	private String name;
	private String adminName;
	private String adminEmail;
	private String albaneroEmail;
	private String orgUrl;
	private List<String> productIdList;
	@DateTimeFormat(style = "M-") 
	@CreatedDate
	private Date created;
	@LastModifiedDate
	private Date updated;
}
