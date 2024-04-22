package com.albanero.authservice.model;

import java.util.List;

import com.albanero.authservice.common.dto.ProjectOrgRoleId;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

@Data
@Document(collection = "userOrgRole")
public class UserOrgRole {
	@Id
	String id;
	@Indexed
	String userId;
	List<String> orgRoleIdList;
	List<String> platformRoleIdList;
	List<ProjectOrgRoleId> projectOrgRoleIdList;
}
