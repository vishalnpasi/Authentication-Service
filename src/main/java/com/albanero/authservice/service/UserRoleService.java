package com.albanero.authservice.service;

import jakarta.servlet.http.HttpServletRequest;

import com.albanero.authservice.common.dto.request.*;
import com.albanero.authservice.common.dto.response.ModuleNameDto;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.stereotype.Service;

import com.albanero.authservice.common.dto.response.BaseResponse;
import com.albanero.authservice.common.dto.response.DefaultRolePermissions;
import com.albanero.authservice.model.Role;
import com.albanero.authservice.model.UserOrgRole;
import com.albanero.authservice.model.UserProfile;

import java.net.URISyntaxException;
import java.util.List;

@Service
@RefreshScope
public interface UserRoleService {
	public void setUserIdDetails(UserProfile userProfile, UserIdDetails userIdDetails);

	public BaseResponse getUserMappings(HttpServletRequest request, AuthRequest authRequest);
	
	public BaseResponse validateUserMappings(UserIdDetails userIdDetails, UserProfile userProfile);

	public DefaultRolePermissions setDefaultRolePermissions(Role role);

	public UserIdDetails fetchUserIdDetails(UserOrgRole userOrgRole, AuthRequest authRequest, UserProfile userProfile);

	public BaseResponse authorizeApiRoutes(HttpServletRequest request, ApiDetails apiDetails);
	
	public UserProfileDetails setUserProfileDetails(UserProfile userProfile);
	
	public UserProfileDetails setUserProfileDetailsWithoutImg(UserProfile userProfile);
	
	public BaseResponse updateUserRolesInProject(HttpServletRequest request, UserProfileDetails userProfileDetails);
	
	public BaseResponse updateUserRolesInOrg(HttpServletRequest request, UserProfileDetails userProfileDetails);

    public BaseResponse syncRolesToProjectOrg();

	public BaseResponse addRolesToUsers();

	public Boolean authorizeIamRoutes(HttpServletRequest request, UserProfile userProfile) throws URISyntaxException;

	public BaseResponse addOrgWatcherToUsers();

    public List<ModuleNameDto> userRolePermissions(HttpServletRequest httpServletRequest);
}
