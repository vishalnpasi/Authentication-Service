package com.albanero.authservice.controller;

import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;

import com.albanero.authservice.common.constants.PathVariables;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.albanero.authservice.common.constants.MappingConstants;
import com.albanero.authservice.common.constants.OrgConstants;
import com.albanero.authservice.common.constants.ProductConstants;
import com.albanero.authservice.common.constants.RequestParams;
import com.albanero.authservice.common.dto.request.AddRemoveMemberRequest;
import com.albanero.authservice.common.dto.request.OrgLevelDetails;
import com.albanero.authservice.common.dto.request.RegistrationUser;
import com.albanero.authservice.common.dto.response.BaseResponse;
import com.albanero.authservice.service.OrganizationService;

import java.io.UnsupportedEncodingException;
import java.util.Optional;

import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_END_LOG_TAG;
import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_START_LOG_TAG;

@RestController
@RequestMapping(MappingConstants.API_USER_BASE)
public class OrganizationController {

	private static final Logger LOGGER = LoggerFactory.getLogger(OrganizationController.class);
	private static final String ORGANIZATION_CONTROLLER = "OrganizationController";

	private final OrganizationService orgService;

	@Autowired
	public OrganizationController(OrganizationService orgService) {
		this.orgService = orgService;
	}

	/**
	 * REST API responsible to create organization
	 * 
	 * @param orgDetails  {@link OrgLevelDetails}
	 * @return {@link BaseResponse}
	 */
	@PostMapping(OrgConstants.USER_ORG)
	public ResponseEntity<BaseResponse> createOrganization(HttpServletRequest request,
			@RequestBody OrgLevelDetails orgDetails) {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, ORGANIZATION_CONTROLLER,"createOrganization");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = orgService.createOrganization(request, orgDetails);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, ORGANIZATION_CONTROLLER, "createOrganization",(System.currentTimeMillis() - startTime));
		return new ResponseEntity<>(baseResponse, HttpStatus.OK);
	}

	/**
	 * REST API responsible to verify organization
	 * 
	 * @param orgDetails  {@link OrgLevelDetails}
	 * @return {@link BaseResponse}
	 */
	@PostMapping(OrgConstants.VERIFY_ORG)
	public ResponseEntity<BaseResponse> verifyOrganization(HttpServletRequest request,
			@RequestBody OrgLevelDetails orgDetails) {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, ORGANIZATION_CONTROLLER, "verifyOrganization");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = orgService.verifyOrg(request, orgDetails);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, ORGANIZATION_CONTROLLER, "verifyOrganization", (System.currentTimeMillis() - startTime));
		return new ResponseEntity<>(baseResponse, HttpStatus.OK);
	}

	/**
	 * REST API responsible to add members to the organization
	 *
	 * @param request  {@link HttpServletRequest}
	 * @param addMemberRequest {@link AddRemoveMemberRequest}
	 * @return  {@link BaseResponse}
	 */
	@PostMapping(OrgConstants.ORG_MEMBER)
	public ResponseEntity<BaseResponse> addOrgMember(HttpServletRequest request,
			@RequestBody AddRemoveMemberRequest addMemberRequest) throws MessagingException, UnsupportedEncodingException {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, ORGANIZATION_CONTROLLER, "inviteOrgMember");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = orgService.addOrgMember(request, addMemberRequest);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, ORGANIZATION_CONTROLLER,"inviteOrgMember", (System.currentTimeMillis() - startTime));
		return new ResponseEntity<>(baseResponse, HttpStatus.OK);
	}

	/**
	 * REST API responsible to update members to the organization
	 *
	 * @param request  {@link HttpServletRequest}
	 * @param updateMemberRequest  {@link RegistrationUser}
	 * @return {@link BaseResponse}
	 */
	@PutMapping(OrgConstants.ORG_MEMBER)
	public ResponseEntity<BaseResponse> updateOrgMember(HttpServletRequest request,
			@RequestBody RegistrationUser updateMemberRequest) throws MessagingException, UnsupportedEncodingException {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, ORGANIZATION_CONTROLLER, "updateOrgMember");		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = orgService.updateOrgMember(request, updateMemberRequest);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, ORGANIZATION_CONTROLLER,"updateOrgMember",(System.currentTimeMillis() - startTime));
		return new ResponseEntity<>(baseResponse, HttpStatus.OK);
	}

	/**
	 * REST API responsible to update organization
	 *
	 * @param request  {@link HttpServletRequest}
	 * @param orgDetails  {@link OrgLevelDetails}
	 * @return {@link BaseResponse}
	 */
	@PutMapping(OrgConstants.USER_ORG)
	public ResponseEntity<BaseResponse> updateOrganization(HttpServletRequest request,
			@RequestBody OrgLevelDetails orgDetails) {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, ORGANIZATION_CONTROLLER,"updateOrganization");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = orgService.updateOrganization(request, orgDetails);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, ORGANIZATION_CONTROLLER, "updateOrganization",(System.currentTimeMillis() - startTime));
		return new ResponseEntity<>(baseResponse, HttpStatus.OK);
	}

	/**
	 * REST API responsible to fetch organizationRolePermissions
	 * 
	 * @param request  {@link HttpServletRequest}
	 * @param orgDetails  {@link OrgLevelDetails}
	 * @return {@link BaseResponse}
	 */
	@PostMapping(OrgConstants.ORG_ROLE_PERMISSIONS)
	public ResponseEntity<BaseResponse> fetchOrgRolePermissions(HttpServletRequest request,
			@RequestBody OrgLevelDetails orgDetails) {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, ORGANIZATION_CONTROLLER, "fetchOrgRolePermissions");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = orgService.createOrganization(request, orgDetails);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, ORGANIZATION_CONTROLLER,"fetchOrgRolePermissions", (System.currentTimeMillis() - startTime));
		return new ResponseEntity<>(baseResponse, HttpStatus.OK);
	}

	/**
	 * REST API responsible to get organization details
	 * 
	 * @param request  {@link HttpServletRequest}
	 * @return {@link BaseResponse}
	 */
	@GetMapping(OrgConstants.USER_ORG)
	public ResponseEntity<BaseResponse> getOrganizationDetails(HttpServletRequest request) {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, ORGANIZATION_CONTROLLER, "getOrganizationDetails");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = orgService.fetchListOfOrgs(request);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, ORGANIZATION_CONTROLLER, "getOrganizationDetails", (System.currentTimeMillis() - startTime));
		return new ResponseEntity<>(baseResponse, HttpStatus.OK);
	}

	/**
	 * REST API responsible to fetch all platform products
	 *
	 * @return {@link BaseResponse}
	 */
	@GetMapping(ProductConstants.ALL_PRODUCTS)
	public ResponseEntity<BaseResponse> getAllProducts() {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, ORGANIZATION_CONTROLLER, "getAllProducts");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = orgService.fetchListOfProducts();
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, ORGANIZATION_CONTROLLER, "getAllProducts", (System.currentTimeMillis() - startTime));
		return new ResponseEntity<>(baseResponse, HttpStatus.OK);
	}

	/**
	 * REST API responsible to fetch all platform products
	 * 
	 * @param orgId  {@link String}
	 * @return {@link BaseResponse}
	 */
	@GetMapping(OrgConstants.ORG_PRODUCTS)
	public ResponseEntity<BaseResponse> fetchProductsOfOrg(@PathVariable(RequestParams.ORG_ID) String orgId) {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, ORGANIZATION_CONTROLLER, "fetchProductsOfOrg");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = orgService.fetchListOfProductsForOrganization(orgId);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, ORGANIZATION_CONTROLLER, "fetchProductsOfOrg", (System.currentTimeMillis() - startTime));
		return new ResponseEntity<>(baseResponse, HttpStatus.OK);
	}

	/**
	 * REST API responsible to fetch default Roles
	 *
	 * @param orgId  {@link Optional}
	 * @param page  {@link Integer}
	 * @param pageSize {@link Integer}
	 * @return  {@link BaseResponse}
	 */
	@GetMapping(OrgConstants.DEFAULT_ROLES)
	public ResponseEntity<BaseResponse> fetchDefaultRoles(@RequestParam(required = false) Optional<String> orgId,  @RequestParam(defaultValue = "0") Integer page, @RequestParam(defaultValue = "10") Integer pageSize) {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, ORGANIZATION_CONTROLLER, "fetchDefaultRoles");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = orgService.fetchOrgDefaultRoles(orgId, page, pageSize);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, ORGANIZATION_CONTROLLER, "fetchDefaultRoles", (System.currentTimeMillis() - startTime));
		return new ResponseEntity<>(baseResponse, HttpStatus.OK);
	}

	/**
	 * REST API responsible to fetch users in organisation
	 *
	 * @param request {@link HttpServletRequest}
	 * @param orgLevelDetails  {@link OrgLevelDetails}
	 * @param userStatus  {@link Optional}
	 * @return  {@link BaseResponse}
	 */
	@PostMapping(OrgConstants.USERS_IN_ORG)
	public ResponseEntity<BaseResponse> getUsersInOrg(HttpServletRequest request,
													  @RequestBody OrgLevelDetails orgLevelDetails, @RequestParam(required = false) Optional<String> userStatus) throws JsonProcessingException {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, ORGANIZATION_CONTROLLER, "getUsersInOrg");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = new BaseResponse();
			if (userStatus.isPresent()) {
				if (userStatus.get().equals("unapproved")) {
					baseResponse = orgService.fetchListOfUnapprovedUsersInOrg(request, orgLevelDetails);
				} else if (userStatus.get().equals("active") ) {
					baseResponse = orgService.fetchListOfActiveUsersInOrg(request, orgLevelDetails);
				} else if (userStatus.get().equals("inactive") ){
					baseResponse = orgService.fetchListOfInactiveUsersInOrg(request, orgLevelDetails);
				} else if (userStatus.get().equals("block") ) {
					baseResponse = orgService.fetchListOfBlockedUsersInOrg(request, orgLevelDetails);
				}
			}  else {
				baseResponse = orgService.fetchListOfUsersInOrg(request, orgLevelDetails);
			}
			LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, ORGANIZATION_CONTROLLER, "getUsersInOrg", (System.currentTimeMillis() - startTime));
		return new ResponseEntity<>(baseResponse, HttpStatus.OK);
	}

	/**
	 * REST API responsible to fetch unApproved User in Org
	 *
	 * @param request  {@link HttpServletRequest}
	 * @param orgLevelDetails  {@link OrgLevelDetails}
	 * @return  {@link BaseResponse}
	 */
	@PostMapping(OrgConstants.UNAPPROVED_USERS_IN_ORG)
	public ResponseEntity<BaseResponse> getUnapprovedUsersInOrg(HttpServletRequest request,
														  @RequestBody OrgLevelDetails orgLevelDetails) throws JsonProcessingException {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, ORGANIZATION_CONTROLLER, "getUnapprovedUsersInOrg");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = orgService.fetchListOfUnapprovedUsersInOrg(request, orgLevelDetails);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, ORGANIZATION_CONTROLLER, "getUnapprovedUsersInOrg", (System.currentTimeMillis() - startTime));
		return new ResponseEntity<>(baseResponse, HttpStatus.OK);
	}

	/**
	 * REST API responsible to fetch organization details
	 *
	 * @param orgId {@link String}
	 * @return {@link BaseResponse}
	 */
	@GetMapping(OrgConstants.ORG_DETAILS + PathVariables.ORG_ID_PARAM)
	public ResponseEntity<BaseResponse> fetchOrganizationDetails(@PathVariable(RequestParams.ORG_ID) String orgId) {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, ORGANIZATION_CONTROLLER, "fetchOrganizationDetails");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = orgService.fetchOrganizationDetails(orgId);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, ORGANIZATION_CONTROLLER, "fetchOrganizationDetails", (System.currentTimeMillis() - startTime));
		return new ResponseEntity<>(baseResponse, HttpStatus.OK);
	}


	/**
	 * REST API responsible to remove members from the organization
	 * 
	 * @param request  {@link HttpServletRequest}
	 * @param addMemberRequest  {@link AddRemoveMemberRequest}
	 * @return {@link BaseResponse}
	 */
	@DeleteMapping(OrgConstants.ORG_MEMBER)
	public ResponseEntity<BaseResponse> removeOrgMember(HttpServletRequest request,
			@RequestBody AddRemoveMemberRequest addMemberRequest) {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, ORGANIZATION_CONTROLLER, "removeOrgMember");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = orgService.removeOrgMember(request, addMemberRequest);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, ORGANIZATION_CONTROLLER, "removeOrgMember", (System.currentTimeMillis() - startTime));
		return new ResponseEntity<>(baseResponse, HttpStatus.OK);
	}
}
