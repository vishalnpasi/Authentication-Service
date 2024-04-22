package com.albanero.authservice.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

@Data
@Document(collection = "projectOrgRole")
public class ProjectOrgRole {
	@Id
	private String id;
	private String projectOrgId;
	private String roleId;
}
