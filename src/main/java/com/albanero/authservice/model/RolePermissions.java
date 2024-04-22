package com.albanero.authservice.model;

import java.util.List;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

@Data
@Document(collection = "rolePermissions")
public class RolePermissions {
	@Id
	String id;
	@Indexed(unique = true)
	String roleId;
	List<String> permissionIdList;
}
