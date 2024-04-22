package com.albanero.authservice.common.dto.request;

import java.util.List;

import com.albanero.authservice.model.Product;
import com.albanero.authservice.model.Project;
import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

import jakarta.validation.constraints.NotBlank;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OrgLevelDetails {
	@NotBlank
	String orgId;
	String orgName;
	String adminName;
	String adminEmail;
	String albaneroEmail;
	String newOrgName;
	String orgUrl;
	String role;
	String roleId;
	List<String> rolePermissions;
	List<String> productIdList;
	List<Product> productDetails;
	List<Project> projectDetails;
}
