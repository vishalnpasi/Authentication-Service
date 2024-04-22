package com.albanero.authservice.common.dto.request;

import java.util.Date;
import java.util.List;

import com.albanero.authservice.common.dto.response.ProfileImageDetails;
import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserProfileDetails {
	private String id;
	private String userId;
	private String username;
	private String emailId;
	private String firstName;
	private String lastName;
	private String fullName;
	private String role;
	private String defaultRole;
	private List<String> userRoles;
	private String orgId;
	private String projectId;
	private ProfileImageDetails profileImageDetails;
	private Boolean isAccountApproved;
	private Boolean isAccountActive;
	private Boolean isAccountBlock;
	private List<String> projectList;
	private String statusChangedBy;
	private Date statusChangedAt;
}
