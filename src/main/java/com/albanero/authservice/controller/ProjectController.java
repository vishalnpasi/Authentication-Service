package com.albanero.authservice.controller;

import com.albanero.authservice.common.constants.MappingConstants;
import com.albanero.authservice.common.constants.ProjectConstants;
import com.albanero.authservice.common.constants.PathVariables;
import com.albanero.authservice.common.constants.RequestParams;
import com.albanero.authservice.common.dto.request.AddMembersRequest;
import com.albanero.authservice.common.dto.request.AddRemoveMemberRequest;
import com.albanero.authservice.common.dto.request.ProjectLevelDetails;
import com.albanero.authservice.common.dto.response.BaseResponse;
import com.albanero.authservice.common.util.RestUtil;
import com.albanero.authservice.service.ProjectService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;

import static com.albanero.authservice.common.constants.LoggerConstants.*;

@RestController
@RequestMapping(MappingConstants.API_USER_BASE)
public class ProjectController {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProjectController.class);
	private static final String PROJECT_CONTROLLER = "ProjectController";
	private final ProjectService projectService;

	@Autowired
	public ProjectController(ProjectService projectService) {
		this.projectService = projectService;
	}

	/**
	 * REST API responsible to create project
	 *
	 * @param request  {@link HttpServletRequest}
	 * @param projectDetails  {@link ProjectLevelDetails}
	 * @return {@link BaseResponse}
	 */
	@PostMapping(ProjectConstants.ORG_PROJECT)
	public ResponseEntity<BaseResponse> createProject(HttpServletRequest request,
			@RequestBody ProjectLevelDetails projectDetails) {
		String method = "createProject";
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, PROJECT_CONTROLLER,method);
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = projectService.createOrgProject(request, projectDetails);
			LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, PROJECT_CONTROLLER,method, (System.currentTimeMillis() - startTime));
			if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.NOT_FOUND.toString())) {
				return new ResponseEntity<>(baseResponse, HttpStatus.UNAUTHORIZED);
			} else if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.FORBIDDEN.toString())) {
				return new ResponseEntity<>(baseResponse, HttpStatus.FORBIDDEN);
			} else if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.INTERNAL_SERVER_ERROR.toString())) {
				return new ResponseEntity<>(baseResponse, HttpStatus.INTERNAL_SERVER_ERROR);
			} else {
				return new ResponseEntity<>(baseResponse, HttpStatus.OK);
			}
	}

	/**
	 * REST API responsible to fetch default project Roles
	 *
	 * @param projectId  {@link Optional}
	 * @param orgId  {@link Optional}
	 * @param page  {@link Integer}
	 * @param pageSize  {@link Integer}
	 * @return  {@link BaseResponse}
	 */
	@GetMapping(ProjectConstants.DEFAULT_ROLES)
	public ResponseEntity<BaseResponse> fetchDefaultRoles(@RequestParam(required = false) Optional<String> projectId, @RequestParam(required = false) Optional<String> orgId, @RequestParam(defaultValue = "0") Integer page, @RequestParam(defaultValue = "10") Integer pageSize) {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, PROJECT_CONTROLLER, "fetchDefaultRoles");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = projectService.fetchProjectDefaultRoles(projectId, orgId ,page, pageSize);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, PROJECT_CONTROLLER, "fetchDefaultRoles", (System.currentTimeMillis() - startTime));
		return ResponseEntity.ok(baseResponse);

	}

	/**
	 * REST API responsible to verify project
	 *
	 * @param request {@link HttpServletRequest}
	 * @param projectDetails  {@link ProjectLevelDetails}
	 * @return  {@link BaseResponse}
	 */
	@PostMapping(ProjectConstants.VERIFY_PROJECT)
	public ResponseEntity<BaseResponse> verifyProject(HttpServletRequest request,
			@RequestBody ProjectLevelDetails projectDetails){
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, PROJECT_CONTROLLER, "verifyProject");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = projectService.verifyOrgProject(request, projectDetails);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, PROJECT_CONTROLLER,"verifyProject", (System.currentTimeMillis() - startTime));
		return ResponseEntity.ok(baseResponse);
	}

	/**
	 * REST API responsible to Adding Multiple members into Project
	 * 
	 * @param request {@link HttpServletRequest}
	 * @param addMembersRequest  {@link AddMembersRequest}
	 * @return {@link ResponseEntity<BaseResponse>}
	 */
	@PostMapping(ProjectConstants.PROJECT_MEMBER)
	public ResponseEntity<BaseResponse> addProjectMember(HttpServletRequest request,
		@RequestBody AddMembersRequest addMembersRequest)
	{
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, PROJECT_CONTROLLER, "addProjectMember");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = projectService.addProjectMember(request, addMembersRequest);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, PROJECT_CONTROLLER, "addProjectMember", (System.currentTimeMillis() - startTime));
		return RestUtil.getResponseEntity(baseResponse, HttpStatus.OK);
	}

	/**
	 * REST API responsible to get all projectDetails in an organization
	 *
	 * @param request {@link HttpServletRequest}
	 * @param orgId  {@link String}
	 * @return  {@link BaseResponse}
	 */
	@GetMapping(ProjectConstants.ORG_PROJECT_DETAILS)
	public ResponseEntity<BaseResponse> getProjectDetails(HttpServletRequest request,
			@PathVariable(RequestParams.ORG_ID) String orgId) {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, PROJECT_CONTROLLER, "getProjectDetails");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = projectService.fetchListOfProjects(request, orgId);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, PROJECT_CONTROLLER, "getProjectDetails", (System.currentTimeMillis() - startTime));
		return ResponseEntity.ok(baseResponse);

	}

	/**
	 * REST API responsible to get users of a Project
	 *
	 * @param request  {@link HttpServletRequest}
	 * @param projectLevelDetails  {@link ProjectLevelDetails}
	 * @return  {@link BaseResponse}
	 */
	@PostMapping(ProjectConstants.USERS_IN_PROJECT)
	public ResponseEntity<BaseResponse> getUsersInProject(HttpServletRequest request,
			@RequestBody ProjectLevelDetails projectLevelDetails){
		String method = "getUsersInProject";
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, PROJECT_CONTROLLER, method);
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = projectService.fetchListOfUsersInProject(request, projectLevelDetails);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, PROJECT_CONTROLLER, method, (System.currentTimeMillis() - startTime));
		return ResponseEntity.ok(baseResponse);
	}

	/**
	 * REST API responsible to remove a member from project and removing org watcher role from organization iif user is not part of any other project in the Organization
	 * 
	 * @param request {@link HttpServletRequest}
	 * @param addMemberRequest  {@link AddRemoveMemberRequest}
	 * @return {@link BaseResponse}
	 */
	@PutMapping(ProjectConstants.PROJECT_MEMBER)
	public ResponseEntity<BaseResponse> removeProjectMember(HttpServletRequest request,
			@RequestBody AddRemoveMemberRequest addMemberRequest)  {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, PROJECT_CONTROLLER, "removeProjectMember");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = projectService.removeProjectMember(request, addMemberRequest);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, PROJECT_CONTROLLER, "removeProjectMember", (System.currentTimeMillis() - startTime));
		return ResponseEntity.ok(baseResponse);
	}

	/**
	 * REST API responsible to fetch all user associated projects
	 *
	 * @return {@link BaseResponse}
	 */
	@PostMapping(ProjectConstants.USER_PROJECTS)
	public ResponseEntity<BaseResponse> getUserProjects(HttpServletRequest request) {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, PROJECT_CONTROLLER, "getUserProjects");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = projectService.fetchUserProjects(request);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, PROJECT_CONTROLLER, "getUserProjects", (System.currentTimeMillis() - startTime));
		return ResponseEntity.ok(baseResponse);
	}

	/**
	 * REST API responsible to set user default project
	 *
	 * @param projectId  {@link String}
	 * @param orgId  {@link String}
	 * @return {@link BaseResponse}
	 */
	@PostMapping(ProjectConstants.USER_DEFAULT_PROJECT + PathVariables.PROJECT_ID_PARAM)
	public ResponseEntity<BaseResponse> setUserDefaultProject(HttpServletRequest request, @PathVariable(RequestParams.PROJECT_ID) String projectId, @RequestParam(RequestParams.ORG_ID) String orgId) {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, PROJECT_CONTROLLER, "setUserDefaultProject");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = projectService.setUserDefaultProject(request, orgId, projectId);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, PROJECT_CONTROLLER, "setUserDefaultProject", (System.currentTimeMillis() - startTime));
		return ResponseEntity.ok(baseResponse);
	}

	/**
	 * REST API responsible to fetch user default project
	 *
	 * @param orgId  {@link String}
	 * @param request  {@link HttpServletRequest}
	 * @return {@link BaseResponse}
	 */
	@GetMapping(ProjectConstants.USER_DEFAULT_PROJECT + PathVariables.ORG_ID_PARAM)
	public ResponseEntity<BaseResponse> fetchUserDefaultProject(HttpServletRequest request, @PathVariable(RequestParams.ORG_ID) String orgId){
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, PROJECT_CONTROLLER, "fetchUserDefaultProject");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = projectService.fetchUserDefaultProject(request,orgId);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, PROJECT_CONTROLLER, "fetchUserDefaultProject", (System.currentTimeMillis() - startTime));
		return ResponseEntity.ok(baseResponse);
	}

	/**
	 * REST API responsible to remove user default project
	 *
	 * @param orgId {@link String}
	 * @return {@link BaseResponse}
	 */
	@PutMapping(ProjectConstants.USER_REMOVE_DEFAULT_PROJECT + PathVariables.ORG_ID_PARAM)
	public ResponseEntity<BaseResponse> removeUserDefaultProject(HttpServletRequest request, @PathVariable(RequestParams.ORG_ID) String orgId) {
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, PROJECT_CONTROLLER, "removeUserDefaultProject");
		long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = projectService.removeUserDefaultProject(request, orgId);
		LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, PROJECT_CONTROLLER, "removeUserDefaultProject", (System.currentTimeMillis() - startTime));
		return ResponseEntity.ok(baseResponse);
	}
}
