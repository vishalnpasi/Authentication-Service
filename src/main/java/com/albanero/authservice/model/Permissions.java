package com.albanero.authservice.model;

import java.util.List;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

import jakarta.validation.constraints.NotBlank;

@Data
@Document(collection = "permissions")
public class Permissions {
	@Id
	String id;
	List<String> allowedEndpointIdList;
	String permission;
	String screen;
	@NotBlank
	String description;
	@NotBlank
	String permissionTitle;
	String subModuleId;
	String moduleId;
}
