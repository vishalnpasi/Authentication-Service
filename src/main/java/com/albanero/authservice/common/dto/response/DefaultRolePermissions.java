package com.albanero.authservice.common.dto.response;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DefaultRolePermissions {
	private String role;
	private List<String> rolePermissions;
	private String description;
}
