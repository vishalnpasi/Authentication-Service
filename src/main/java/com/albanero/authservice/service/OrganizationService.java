package com.albanero.authservice.service;

import java.io.UnsupportedEncodingException;
import java.util.Optional;

import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.stereotype.Service;

import com.albanero.authservice.common.dto.request.AddRemoveMemberRequest;
import com.albanero.authservice.common.dto.request.OrgLevelDetails;
import com.albanero.authservice.common.dto.request.RegistrationUser;
import com.albanero.authservice.common.dto.response.BaseResponse;

@Service
public interface OrganizationService {

	public BaseResponse createOrganization(HttpServletRequest request, OrgLevelDetails orgDetails);

	public BaseResponse updateOrganization(HttpServletRequest request, OrgLevelDetails orgDetails);

	public BaseResponse addOrgMember(HttpServletRequest request, AddRemoveMemberRequest addMemberRequest) throws UnsupportedEncodingException, MessagingException;

	public BaseResponse fetchListOfInactiveUsersInOrg(HttpServletRequest request, OrgLevelDetails orgLevelDetails) throws JsonProcessingException;

	public BaseResponse removeOrgMember(HttpServletRequest request, AddRemoveMemberRequest addMemberRequest);

	public BaseResponse verifyOrg(HttpServletRequest request, OrgLevelDetails orgDetails);

	public BaseResponse updateOrgMember(HttpServletRequest request, RegistrationUser addMemberRequest) throws MessagingException, UnsupportedEncodingException;

	public BaseResponse fetchListOfOrgs(HttpServletRequest request);

	public BaseResponse fetchListOfProducts();

	public BaseResponse fetchListOfProductsForOrganization(String orgId);

	public BaseResponse fetchOrgDefaultRoles(Optional<String> orgId, Integer page, Integer pageSize);

	public BaseResponse fetchListOfUsersInOrg(HttpServletRequest request, OrgLevelDetails orgLevelDetails) throws JsonProcessingException;

	public BaseResponse fetchListOfActiveUsersInOrg(HttpServletRequest request, OrgLevelDetails orgLevelDetails) throws JsonProcessingException;

	public BaseResponse fetchListOfUnapprovedUsersInOrg(HttpServletRequest request, OrgLevelDetails orgLevelDetails) throws JsonProcessingException;

	public BaseResponse fetchListOfBlockedUsersInOrg(HttpServletRequest request, OrgLevelDetails orgLevelDetails) throws JsonProcessingException;

	public BaseResponse fetchOrganizationDetails(String orgId);
}
