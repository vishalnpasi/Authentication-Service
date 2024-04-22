package com.albanero.authservice.common.dto.response;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
public class UserPermissions {
	List<Permissions> permissions;
	String encryptedPermissions;
	String secretToEncryptPermissions;
}
