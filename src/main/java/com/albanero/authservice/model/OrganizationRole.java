package com.albanero.authservice.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

@Data
@Document(collection = "organizationRole")
public class OrganizationRole {
	@Id
	String id;
	String orgId;
	String roleId;
}
