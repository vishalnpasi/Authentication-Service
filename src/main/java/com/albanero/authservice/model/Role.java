package com.albanero.authservice.model;

import java.util.List;

import com.albanero.authservice.common.dto.response.CreatedDetailsDto;
import com.albanero.authservice.common.dto.response.UpdatedDetailsDto;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;
import org.springframework.data.mongodb.core.mapping.Field;

@Data
@Document(collection = "role")
public class Role {
	@Id
	private String id;
	@Field(name = "role")
	@JsonProperty(value = "role")
	private String roleName;
	private List<String> permissionIdList;
	private RoleType roleType;
	private String description;
	private CreatedDetailsDto created;
	private UpdatedDetailsDto updated;

	public void setCreated (UserProfile userProfile) {
		CreatedDetailsDto createdDetailsDto = new CreatedDetailsDto();
		createdDetailsDto.setCreatedById(userProfile.getId());
		createdDetailsDto.setCreatedByUserName(userProfile.getUsername());
		createdDetailsDto.setCreatedAt(System.currentTimeMillis());

		this.created = createdDetailsDto;
	}

	public void setUpdated (UserProfile userProfile) {
		UpdatedDetailsDto updatedDetailsDto = new UpdatedDetailsDto();
		updatedDetailsDto.setUpdatedById(userProfile.getId());
		updatedDetailsDto.setUpdatedByUserName(userProfile.getUsername());
		updatedDetailsDto.setUpdatedAt(System.currentTimeMillis());

		this.updated = updatedDetailsDto;
	}
}
