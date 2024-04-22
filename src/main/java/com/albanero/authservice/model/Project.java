package com.albanero.authservice.model;

import java.util.Date;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.format.annotation.DateTimeFormat;

import lombok.Data;

@Data
@Document(collection = "project")
public class Project {
	@Id
	private String id;
	private String name;
	private String projectUrl;
	@DateTimeFormat(style = "M-") 
	@CreatedDate
	private Date created;
	@LastModifiedDate
	private Date updated;
}
