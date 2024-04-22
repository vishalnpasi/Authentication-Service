package com.albanero.authservice.service.impl;

import com.albanero.authservice.common.constants.PermissionConstants;
import com.albanero.authservice.common.dto.ProjectOrgRoleId;
import com.albanero.authservice.common.dto.request.*;
import com.albanero.authservice.common.dto.response.AddMemberResponse;
import com.albanero.authservice.common.dto.response.BaseResponse;
import com.albanero.authservice.common.dto.response.PaginatedResponse;
import com.albanero.authservice.common.util.EmailUtil;
import com.albanero.authservice.common.util.HelperUtil;
import com.albanero.authservice.common.util.RequestUtil;
import com.albanero.authservice.exception.ProjectServiceException;
import com.albanero.authservice.model.*;
import com.albanero.authservice.repository.*;
import com.albanero.authservice.service.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.stream.Collectors;

import static com.albanero.authservice.common.constants.CommonLoggingConstants.*;
import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO;
import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG;

@Service
public class ProjectServiceImpl implements ProjectService {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProjectServiceImpl.class);

	public static final String ROLE_ADMIN = "ROLE_ADMIN";

	public static final Long USER_VERIFICATION_TOKEN_DURATION = 3 * 24 * 60 * 60000l;

	private static final String PROJECT_SERVICE_IMPL_CLASS = "ProjectServiceImpl";


	@Value("${jasyptSecret}")
	private String encryptorPassword;

	private final OrgRepository orgRepo;

	private final UserRepository userRepo;

	private final RoleRepository roleRepo;

	private final OrgRoleRepository orgRoleRepo;

	private final UserOrgRoleRepository userOrgRoleRepo;

	private final ProjectOrgRepository projectOrgRepo;

	private final ProjectRepository projectRepo;

	private final ProjectOrgRoleRepository projectOrgRoleRepo;

	private final UserRoleService userRoleService;

	private final HelperUtil helperUtil;

	private final EmailUtil emailUtil;

	private final RequestUtil requestUtil;

	private final UserProjectDefaultsRepository userProjectDefaultsRepository;

	private final TokenService tokenService;

	private final AuthenticationService authService;

	@Autowired
	public ProjectServiceImpl(OrgRepository orgRepo, UserRepository userRepo, RoleRepository roleRepo,
							  OrgRoleRepository orgRoleRepo, UserOrgRoleRepository userOrgRoleRepo,
							  ProjectOrgRepository projectOrgRepo, ProjectRepository projectRepo,
							  ProjectOrgRoleRepository projectOrgRoleRepo, UserRoleService userRoleService,
							  HelperUtil helperUtil, EmailUtil emailUtil, RequestUtil requestUtil,
							  UserProjectDefaultsRepository userProjectDefaultsRepository, TokenService tokenService,
							  AuthenticationService authService) {
		this.orgRepo = orgRepo;
		this.userRepo = userRepo;
		this.roleRepo = roleRepo;
		this.orgRoleRepo = orgRoleRepo;
		this.userOrgRoleRepo = userOrgRoleRepo;
		this.projectOrgRepo = projectOrgRepo;
		this.projectRepo = projectRepo;
		this.projectOrgRoleRepo = projectOrgRoleRepo;
		this.userRoleService = userRoleService;
		this.helperUtil = helperUtil;
		this.emailUtil = emailUtil;
		this.requestUtil = requestUtil;
		this.userProjectDefaultsRepository = userProjectDefaultsRepository;
		this.tokenService = tokenService;
		this.authService = authService;
	}


	@Override
	public BaseResponse createOrgProject(HttpServletRequest request, ProjectLevelDetails projectDetails) {
		BaseResponse baseResponse = new BaseResponse();
		boolean isOrgAdmin = false;
		try {
			String token = requestUtil.extractJwtFromRequest(request);
			String username = requestUtil.usernameFromToken(token);
			UserProfile user = userRepo.findByUsername(username);
			UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(user.getId());
			Role orgAdmin = roleRepo.findByRoleAndRoleType(PermissionConstants.ORG_ADMIN, PermissionConstants.ORGANIZATION_DEFAULT);
			if ( orgAdmin == null )
				return getBaseErrorResponseForCreateOrgProject(baseResponse, "Organization Admin Role not found.", HttpStatus.NOT_FOUND);
			if (userOrgRole != null && userOrgRole.getOrgRoleIdList() != null
					&& !userOrgRole.getOrgRoleIdList().isEmpty()) {

				isOrgAdmin = isOrgAdmin(projectDetails, userOrgRole, isOrgAdmin);

				if (Boolean.FALSE.equals(isOrgAdmin))
					return getBaseErrorResponseForCreateOrgProject(baseResponse, "This user doesn't have the permissions to create project", HttpStatus.FORBIDDEN);

				Role projectAdminRole = roleRepo.findByRoleAndRoleType(PermissionConstants.PROJECT_ADMIN,PermissionConstants.PROJECT_DEFAULT);

				if ( projectAdminRole == null )
					return getBaseErrorResponseForCreateOrgProject(baseResponse, "Project Admin Role not found", HttpStatus.NOT_FOUND);

				Project project = new Project();
				if (helperUtil.checkForDuplicateProjectUrl(projectDetails.getProjectName(), projectDetails.getOrgId()))
					return getBaseErrorResponseForCreateOrgProject(baseResponse, "Cannot create duplicate project", HttpStatus.FORBIDDEN);
				project.setName(projectDetails.getProjectName());
				project.setProjectUrl(projectDetails.getProjectUrl());
				projectRepo.save(project);

				ProjectOrg projectOrg = new ProjectOrg();
				projectOrg.setOrgId(projectDetails.getOrgId());
				projectOrg.setProjectId(project.getId());
				projectOrgRepo.save(projectOrg);

				saveUserOrgRoles(projectOrg, userOrgRole, user);

				baseResponse.setMessage("Successfully created the Project!");
				baseResponse.setSuccess(true);
				baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.OK));
				return baseResponse;
			}
			baseResponse.setMessage("This user doesn't have the permissions to create project");
			baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.FORBIDDEN));
			baseResponse.setSuccess(false);
			return baseResponse;

		} catch (Exception ex) {
			LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG,PROJECT_SERVICE_IMPL_CLASS,"createOrgProject",ex.getMessage(),ex.getStackTrace());
			baseResponse.setMessage("Exception occurred in creating the project");
			baseResponse.setSuccess(false);
			baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
			return baseResponse;
		}
	}

	private boolean isOrgAdmin(ProjectLevelDetails projectDetails, UserOrgRole userOrgRole, boolean isOrgAdmin) {
		for (String orgRoleId : userOrgRole.getOrgRoleIdList()) {
			OrganizationRole orgRole = orgRoleRepo.findByIdAndOrgId(orgRoleId, projectDetails.getOrgId());
			if(orgRole != null){
				Optional<Role> role = roleRepo.findById(orgRole.getRoleId());
				if(role.isPresent() && role.get().getRoleName().equals(PermissionConstants.ORG_ADMIN)){
					isOrgAdmin = true;
					break;
				}
			}
		}
		return isOrgAdmin;
	}

	private void saveUserOrgRoles(ProjectOrg projectOrg, UserOrgRole userOrgRole, UserProfile user) {
		List<Role> projectDefaultRoles = roleRepo.findByProjectDefaultRoleType();
		for ( Role projectDefaultRole : projectDefaultRoles ) {
			ProjectOrgRole projectOrgRole = new ProjectOrgRole();
			projectOrgRole.setProjectOrgId(projectOrg.getId());
			projectOrgRole.setRoleId(projectDefaultRole.getId());
			projectOrgRoleRepo.save(projectOrgRole);
			if ( projectDefaultRole.getRoleName().equals(PermissionConstants.PROJECT_ADMIN) ) {
				List<ProjectOrgRoleId> projectOrgRoleIdList;
				projectOrgRoleIdList = userOrgRole.getProjectOrgRoleIdList() != null
						? userOrgRole.getProjectOrgRoleIdList()
						: new ArrayList<>();

				//Adding latest role of current user who is creating new project
				ProjectOrgRoleId projectOrgRoleId = new ProjectOrgRoleId(projectOrgRole.getId(), true);
				projectOrgRoleIdList.add(projectOrgRoleId);
				userOrgRole.setProjectOrgRoleIdList(projectOrgRoleIdList);
				userOrgRole.setUserId(user.getId());
				userOrgRoleRepo.save(userOrgRole);
			}
		}
	}

	private static BaseResponse getBaseErrorResponseForCreateOrgProject(BaseResponse baseResponse, String message, HttpStatus httpStatus) {
		baseResponse.setMessage(message);
		baseResponse.setSuccess(false);
		baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(httpStatus));
		return baseResponse;
	}

	@Override
	public BaseResponse fetchProjectDefaultRoles(Optional<String> projectId, Optional<String> orgId, Integer page, Integer pageSize) {
		BaseResponse baseResponse = new BaseResponse();
		try {
			List<Role> roles = new ArrayList<>();

			roles.addAll(roleRepo.findByProjectDefaultRoleType());
			if(orgId.isPresent()) {
				roles.addAll(roleRepo.findByOrgIdAndProjectCustomRoleType(orgId));
			} else if(projectId.isPresent()) {
				roles.addAll(roleRepo.findByProjectIdAndProjectCustomRoleType(projectId));
			} else {
				roles.addAll(roleRepo.findByProjectCustomRoleType());
			}
			Pageable pageable = PageRequest.of(page, pageSize);
			PaginatedResponse rolesPaginated = helperUtil.listToPage(roles, pageable);

			baseResponse.setPayload(rolesPaginated);
			baseResponse.setMessage("Default Roles fetched along with corresponding permissions!");
			baseResponse.setSuccess(true);
			return baseResponse;

		} catch (Exception ex) {
			LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG,PROJECT_SERVICE_IMPL_CLASS,"fetchProjectDefaultRoles",ex.getMessage(),ex.getStackTrace());
			baseResponse.setMessage("Exception occured while fetching Default Roles!" + ex.getMessage());
			baseResponse.setSuccess(false);
			baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
			return baseResponse;
		}
	}

	/**
	 * Method for Adding Multiple Members to a Project
	 *
	 * @param request {@link HttpServletRequest}
	 * @param addMemberRequest {@link List<AddMembersRequest>}
	 * @return {@link BaseResponse}
	 */
	@Override
	public BaseResponse addProjectMember(HttpServletRequest request, AddMembersRequest addMemberRequest) {
		BaseResponse response = new BaseResponse();
		List<AddMemberResponse> payload = new ArrayList<>();
		List<MembersDetailsRequest> membersDetails = addMemberRequest.getMembersDetails();
		for (MembersDetailsRequest membersRequest: membersDetails) {
			List<String> emailIds = membersRequest.getEmailIds();
			for (String email : emailIds) {
				String role = membersRequest.getRole();
				AddMemberResponse memberDetails = addMembersProject(request, addMemberRequest, email, role);
				payload.add(memberDetails);
			}
		}
		response.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.OK));
		response.setPayload(payload);
		response.setMessage("Users are added Successfully!");
		response.setSuccess(true);
		return response;
	}

	/**
	 * Method to Add a Member to a Project
	 *
	 * @param request {@link HttpServletRequest}
	 * @param membersRequest {@link AddMembersRequest}
	 * @param email {@link String}
	 * @param roleName {@link String}
	 * @return {@link AddMemberResponse}
	 */
	public AddMemberResponse addMembersProject(HttpServletRequest request, AddMembersRequest membersRequest, String email, String roleName) {
		AddMemberResponse memberDetails = new AddMemberResponse();
		try {
			memberDetails.setSuccess(false);
			memberDetails.setEmail(email);
			UserProfile user = new UserProfile();
			if (!helperUtil.isValidEmail(email)) {
				memberDetails.setMessage("This email is invalid!");
				return memberDetails;
			}
			Role role = roleRepo.findByRoleName(roleName);
			if (role == null) {
				memberDetails.setMessage("Given role is either empty or does not exist");
				return memberDetails;
			}
			Optional<Organization> organization = orgRepo.findById(membersRequest.getOrgId());
			if (organization.isEmpty()) {
				memberDetails.setMessage("Given Organization does not exist!");
				return memberDetails;
			}
			Organization org = organization.get();
			Optional<Project> projectRepoById = projectRepo.findById(membersRequest.getProjectId());
			if (projectRepoById.isEmpty()) {
				memberDetails.setMessage("Given project does not exist!");
				return memberDetails;
			}
			Project project = projectRepoById.get();

			String token = requestUtil.extractJwtFromRequest(request);
			String username = requestUtil.usernameFromToken(token);

			if (!helperUtil.checkForDuplicateEmail(email)) {

				AddRemoveMemberRequest addMemberRequest = new AddRemoveMemberRequest();
				addMemberRequest.setEmail(email);
				addMemberRequest.setRole(roleName);
				addMemberRequest.setOrgId(membersRequest.getOrgId());
				addMemberRequest.setProjectId(membersRequest.getProjectId());
				user.setEmailId(email);
				emailUtil.sendProjectInviteEmail(request, username, addMemberRequest, org, project);

				memberDetails.setMessage("User invited!");
				memberDetails.setSuccess(true);
				return memberDetails;
			}

			Role roleInOrg = roleRepo.findByRoleName(PermissionConstants.ORG_WATCHER);
			OrganizationRole orgRole = orgRoleRepo.findByOrgIdAndRoleId(membersRequest.getOrgId(), roleInOrg.getId());

			ProjectOrg projectOrg = projectOrgRepo.findByProjectIdAndOrgId(project.getId(), org.getId());
			ProjectOrgRole projectOrgRole = projectOrgRoleRepo.findByProjectOrgIdAndRoleId(projectOrg.getId(), role.getId());
			RoleType roleType = role.getRoleType();
			if (projectOrgRole == null) {
				if (helperUtil.checkRoleType(roleType , project.getId(),org.getId())) {
					projectOrgRole = new ProjectOrgRole();
					projectOrgRole.setProjectOrgId(projectOrg.getId());
					projectOrgRole.setRoleId(role.getId());
					projectOrgRoleRepo.save(projectOrgRole);
				} else {
					memberDetails.setMessage("Given role is not associated to the project");
					return memberDetails;
				}
			}

			user = userRepo.findByEmailId(email.toLowerCase());
			memberDetails.setFullname(user.getFirstName() + " " + user.getLastName());
			memberDetails.setRole(roleName);

			UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(user.getId());
			List<ProjectOrgRoleId> projectOrgRoleIdList = userOrgRole.getProjectOrgRoleIdList() != null ? userOrgRole.getProjectOrgRoleIdList() : new ArrayList<>();
			List<String> orgRoleIdList = userOrgRole.getOrgRoleIdList() != null ? userOrgRole.getOrgRoleIdList() : new ArrayList<>();
			List<String> ids = new ArrayList<>();
			projectOrgRoleIdList.forEach(projectOrgRoleId-> ids.add(projectOrgRoleId.getProjectOrganizationRoleId()));
			if (!ids.contains(projectOrgRole.getId())) {
				setProjectOrgRoleIdList(membersRequest, projectOrgRoleIdList, projectOrgRole);
			}
			else {
				memberDetails.setMessage("User is already a member with this role !");
				return memberDetails;
			}
			if(!orgRoleIdList.contains(orgRole.getId())) {
				orgRoleIdList.add(orgRole.getId());
			}
			userOrgRole.setProjectOrgRoleIdList(projectOrgRoleIdList);
			userOrgRole.setOrgRoleIdList(orgRoleIdList);
			userOrgRoleRepo.save(userOrgRole);
			memberDetails.setMessage("User added!");
			memberDetails.setSuccess(true);
			return memberDetails;
		} catch (Exception ex) {
			LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG,PROJECT_SERVICE_IMPL_CLASS,"addMembersProject",ex.getMessage(),ex.getStackTrace());
			memberDetails.setMessage("Failed to added user!");
			return memberDetails;
		}
	}

	private void setProjectOrgRoleIdList(AddMembersRequest membersRequest, List<ProjectOrgRoleId> projectOrgRoleIdList, ProjectOrgRole projectOrgRole) {
		if(userHasDefaultRole(projectOrgRoleIdList, membersRequest.getProjectId())){
			//setting current role as not default role because user already has default role in current project
			projectOrgRoleIdList.add(new ProjectOrgRoleId(projectOrgRole.getId(),false));
		}else{
			//setting current role as default role because user doe not have has default role in current project
			projectOrgRoleIdList.add(new ProjectOrgRoleId(projectOrgRole.getId(),true));
		}
	}

	public boolean userHasDefaultRole(List<ProjectOrgRoleId> projectOrgRoleIdList, String projectId){
		for(ProjectOrgRoleId projectOrgRoleId : projectOrgRoleIdList){
			if(!Objects.isNull(projectOrgRoleId.getIsDefault()) && Boolean.TRUE.equals(projectOrgRoleId.getIsDefault())){
				Optional<ProjectOrgRole> projectOrgRole = projectOrgRoleRepo.findById(projectOrgRoleId.getProjectOrganizationRoleId());
				if(projectOrgRole.isPresent()){
					Optional<ProjectOrg> projectOrg = projectOrgRepo.findById(projectOrgRole.get().getProjectOrgId());
					if(projectOrg.isPresent() && Objects.equals(projectOrg.get().getProjectId(),projectId) ){
						return true;
					}
				}
			}
		}
		return false;
	}

	@Override
	public BaseResponse verifyOrgProject(HttpServletRequest request, ProjectLevelDetails projectDetails) {
		BaseResponse baseResponse = new BaseResponse();
		ObjectMapper mapper = new ObjectMapper();
		try {
			String token = requestUtil.extractJwtFromRequest(request);
			if (token == null) {
				return verifyProjectDetailsIfTokenNull(projectDetails, baseResponse);
			}

			Boolean isTokenValid = tokenService.validateTokenRestTemplate(token);
			if (Boolean.FALSE.equals(isTokenValid))
				return getBaseErrorResponseForCreateOrgProject(baseResponse, "Invalid Token!", HttpStatus.UNAUTHORIZED);
			BaseResponse userIdDetailsResponse = requestUtil.getUserMappings(token);
			UserIdDetails userIdDetails = mapper.convertValue(userIdDetailsResponse.getPayload(), UserIdDetails.class);
			String username = userIdDetails.getUserProfileDetails().getUsername();
			UserProfile dbuser = authService.loadUserProfileByUsername(username);
			UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(dbuser.getId());

			if (userOrgRole != null) {
				List<ProjectOrgRoleId> projectOrgRoleIdList = userOrgRole.getProjectOrgRoleIdList();

				if (projectOrgRoleIdList != null) {
					Project project = projectRepo.findByProjectUrl(projectDetails.getProjectUrl());
					ProjectOrg projectOrg = projectOrgRepo.findByProjectIdAndOrgId(project.getId(),
							projectDetails.getOrgId());
					List<ProjectOrgRole> projectOrgRoleList = projectOrgRoleRepo.findByProjectOrgId(projectOrg.getId());
					for (ProjectOrgRole projectOrgRole : projectOrgRoleList) {
						List<String> ids = new ArrayList<>();
						projectOrgRoleIdList.forEach(projectOrgRoleId-> ids.add(projectOrgRoleId.getProjectOrganizationRoleId()));
						if (!ids.contains(projectOrgRole.getId()))
							return getBaseErrorResponseForCreateOrgProject(baseResponse, "Could not validate project", HttpStatus.INTERNAL_SERVER_ERROR);
					}

					baseResponse.setMessage("Valid Project!");
					baseResponse.setSuccess(true);
					return baseResponse;

				}
			}

			baseResponse.setMessage("Invalid Project!");
			baseResponse.setSuccess(false);
			return baseResponse;

		} catch (Exception ex) {
			LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG,PROJECT_SERVICE_IMPL_CLASS,"verifyOrgProject",ex.getMessage(),ex.getStackTrace());
			baseResponse.setMessage("Exception occurred while verifying Organization Project!");
			baseResponse.setSuccess(false);
			baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
			return baseResponse;
		}
	}

	private BaseResponse verifyProjectDetailsIfTokenNull(ProjectLevelDetails projectDetails, BaseResponse baseResponse) {
		if (projectDetails != null && projectDetails.getProjectUrl() != null) {
			Project project = projectRepo.findByProjectUrl(projectDetails.getProjectUrl());
			if (project != null) {
				baseResponse.setMessage("Valid Project!");
				projectDetails.setProjectName(project.getName());
				projectDetails.setProjectUrl(project.getProjectUrl());
				baseResponse.setSuccess(true);
				return baseResponse;
			}
			baseResponse.setMessage("Invalid Project!");
			baseResponse.setSuccess(false);
			baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
			return baseResponse;
		}
		baseResponse.setMessage("Project Details are empty!");
		baseResponse.setSuccess(false);
		baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.BAD_REQUEST));
		return baseResponse;
	}

	@Override
	public BaseResponse fetchListOfProjects(HttpServletRequest request, String orgId) {
		String method = "fetchListOfProjects";
		BaseResponse baseResponse = new BaseResponse();
		List<ProjectLevelDetails> projectLevelDetailsList = new ArrayList<>();
		ObjectMapper mapper = new ObjectMapper();
		try {
			String token = requestUtil.extractJwtFromRequest(request);
			BaseResponse userIdDetailsResponse = requestUtil.getUserMappings(token);
			UserIdDetails userIdDetails = mapper.convertValue(userIdDetailsResponse.getPayload(), UserIdDetails.class);
			String username = userIdDetails.getUserProfileDetails().getUsername();
			UserProfile dbuser = authService.loadUserProfileByUsername(username);
			UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(dbuser.getId());
			UserProjectDefaults userProjectDefaults = userProjectDefaultsRepository.findByUserIdAndOrgId(dbuser.getId(), orgId);

			if (userOrgRole != null) {
				List<ProjectOrgRoleId> projectOrgRoleIdList = userOrgRole.getProjectOrgRoleIdList();

				List<ProjectOrg> projectOrgList = projectOrgRepo.findByOrgId(orgId);
				List<Project> projectList = new ArrayList<>();
				if (projectOrgRoleIdList != null) {

					for (ProjectOrg projectOrg : projectOrgList) {
						List<ProjectOrgRole> projectOrgRoleList = projectOrgRoleRepo
								.findByProjectOrgId(projectOrg.getId());

						for (ProjectOrgRole projectOrgRole : projectOrgRoleList)
							setProjectLevelDetailsList(projectOrg, projectOrgRole, projectOrgRoleIdList, dbuser, projectList, userProjectDefaults, projectLevelDetailsList);
					}

					baseResponse.setPayload(projectLevelDetailsList);
					baseResponse.setMessage("Project details fetched!");
					baseResponse.setSuccess(true);
					return baseResponse;
				}
			}
			baseResponse.setMessage("Could not fetch project details!");
			baseResponse.setSuccess(false);
			baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
			return baseResponse;

		} catch (Exception e) {
			LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG,PROJECT_SERVICE_IMPL_CLASS,method,e.getMessage(),e.getStackTrace());
			baseResponse.setMessage("Exception occured while fetching project details!");
			baseResponse.setSuccess(false);
			baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
			return baseResponse;
		}
	}

	private void setProjectLevelDetailsList(ProjectOrg projectOrg, ProjectOrgRole projectOrgRole, List<ProjectOrgRoleId> projectOrgRoleIdList, UserProfile dbuser, List<Project> projectList, UserProjectDefaults userProjectDefaults, List<ProjectLevelDetails> projectLevelDetailsList) {
		List<String> ids = new ArrayList<>();
		projectOrgRoleIdList.forEach(projectOrgRoleId-> ids.add(projectOrgRoleId.getProjectOrganizationRoleId()));
		if (ids.contains(projectOrgRole.getId())) {

			Optional<Project> project = projectRepo.findById(projectOrg.getProjectId());
			if(project.isEmpty()){
				LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,PROJECT_SERVICE_IMPL_CLASS, "setProjectLevelDetailsList","Project not found with this projectId ", projectOrg.getProjectId(),USERID, dbuser.getId());
				throw new ProjectServiceException("Project not found with this projectId " + projectOrg.getProjectId(),HttpStatus.NOT_FOUND);
			}

			if (projectList.contains(project.get()))
				return;

			projectList.add(project.get());
			Optional<Role> role = roleRepo.findById(projectOrgRole.getRoleId());
			if(role.isEmpty()){
				LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,PROJECT_SERVICE_IMPL_CLASS, "setProjectLevelDetailsList",ROLE_NOT_FOUND, projectOrgRole.getRoleId(),USERID, dbuser.getId());
				throw new ProjectServiceException(ROLE_NOT_FOUND+ projectOrgRole.getRoleId(),HttpStatus.NOT_FOUND);
			}
			ProjectLevelDetails projectLevelDetails = new ProjectLevelDetails();
			projectLevelDetails.setProjectName(project.get().getName());
			projectLevelDetails.setProjectUrl(project.get().getProjectUrl());
			projectLevelDetails.setOrgId(projectOrg.getOrgId());
			projectLevelDetails.setProjectId(project.get().getId());
			projectLevelDetails.setRole(role.get().getRoleName());
			ProjectOrg projectOrgFindByProjectIdAndOrgId = projectOrgRepo.findByProjectIdAndOrgId(projectLevelDetails.getProjectId(),
					projectLevelDetails.getOrgId());
			List<ProjectOrgRole> projectOrgRoles = projectOrgRoleRepo.findByProjectOrgId(projectOrgFindByProjectIdAndOrgId.getId());

			List<String> projectOrgRoleIds = projectOrgRoles.stream().map(p -> p.getId())
					.toList();

			List<UserOrgRole> userOrgRoleList = userOrgRoleRepo
					.findByProjectOrgRoleIdListIn(projectOrgRoleIds);
			projectLevelDetails.setUsersCount(userOrgRoleList.size());
			projectLevelDetails.setIsDefault(userProjectDefaults != null && projectLevelDetails.getProjectId().equals(userProjectDefaults.getProjectId()));
			projectLevelDetailsList.add(projectLevelDetails);
		}
	}

	@Override
	public BaseResponse fetchListOfUsersInProject(HttpServletRequest request, ProjectLevelDetails projectLevelDetails) {
		String method = "fetchListOfUsersInProject";
		BaseResponse baseResponse = new BaseResponse();
		List<UserProfileDetails> userProfileDetailsList = new ArrayList<>();
		try {
			if (projectLevelDetails != null && projectLevelDetails.getProjectId() != null
					&& projectLevelDetails.getOrgId() != null) {
				ProjectOrg projectOrg = projectOrgRepo.findByProjectIdAndOrgId(projectLevelDetails.getProjectId(),
						projectLevelDetails.getOrgId());
				if (projectOrg != null) {
					List<ProjectOrgRole> projectOrgRoleList = projectOrgRoleRepo.findByProjectOrgId(projectOrg.getId());

					List<String> projectOrgRoleIdList = projectOrgRoleList.stream().map(p -> p.getId())
							.toList();

					List<UserOrgRole> userOrgRoleList = userOrgRoleRepo
							.findByProjectOrgRoleIdListIn(projectOrgRoleIdList);

					if (userOrgRoleList != null) {
						for (UserOrgRole userOrgRole : userOrgRoleList)
							setUserProfileDetails(projectLevelDetails, userOrgRole, projectOrgRoleIdList, projectOrgRoleList, userProfileDetailsList);
						baseResponse.setMessage("Successfully fetched users belonging to the project");
						baseResponse.setPayload(userProfileDetailsList);
						baseResponse.setSuccess(true);
						return baseResponse;
					}
				}
			}
			baseResponse.setMessage("Could not fetch users");
			baseResponse.setSuccess(false);
			return baseResponse;

		} catch (Exception e) {
			LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG,PROJECT_SERVICE_IMPL_CLASS,method,e.getMessage(),e.getStackTrace());
			baseResponse.setMessage("Exception occurred while fetching users");
			baseResponse.setSuccess(false);
			baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.INTERNAL_SERVER_ERROR));
			return baseResponse;
		}
	}

	private void setUserProfileDetails(ProjectLevelDetails projectLevelDetails, UserOrgRole userOrgRole, List<String> projectOrgRoleIdList, List<ProjectOrgRole> projectOrgRoleList, List<UserProfileDetails> userProfileDetailsList) {
		Optional<UserProfile> user = userRepo.findById(userOrgRole.getUserId());
		if(user.isEmpty()){
			LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,PROJECT_SERVICE_IMPL_CLASS, "setUserProfileDetails","User not found with this userId {}", userOrgRole.getUserId(),"projectId", projectLevelDetails.getProjectId());
			throw new ProjectServiceException("User not found with this userId "+ userOrgRole.getUserId(),HttpStatus.NOT_FOUND);
		}
		UserProfileDetails userProfileDetails = userRoleService.setUserProfileDetailsWithoutImg(user.get());


		List<ProjectOrgRoleId> projectOrgRoleIds = new ArrayList<>();

		for (ProjectOrgRoleId projectOrgRoleId : userOrgRole.getProjectOrgRoleIdList()) {
			if (projectOrgRoleIdList.contains(projectOrgRoleId.getProjectOrganizationRoleId())) {
				projectOrgRoleIds.add(projectOrgRoleId);
			}
		}

		List<String> ids = new ArrayList<>();
		projectOrgRoleIds.forEach(projectOrgRoleId-> ids.add(projectOrgRoleId.getProjectOrganizationRoleId()));

		List<String> userRoles = projectOrgRoleList.stream()
				.filter(p -> ids.contains(p.getId()))
				.map(p -> {
					Optional<Role> role= roleRepo.findById(p.getRoleId());
					if(role.isEmpty()){
						LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,PROJECT_SERVICE_IMPL_CLASS, "setUserProfileDetails","Role not found with this roleId {}",p.getRoleId(),"projectId", projectLevelDetails.getProjectId());
						throw new ProjectServiceException(String.valueOf(ROLE_NOT_FOUND+p.getRoleId()),HttpStatus.NOT_FOUND);
					}
					return role.get().getRoleName();
				})
				.toList();

		userProfileDetails.setUserRoles(userRoles);
		userProfileDetails.setProjectId(projectLevelDetails.getProjectId());

		userProfileDetailsList.add(userProfileDetails);
	}

	@Override
	public BaseResponse removeProjectMember(HttpServletRequest request, AddRemoveMemberRequest removeMemberRequest) {
		String method = "removeProjectMember";
		BaseResponse baseResponse = new BaseResponse();
		if (removeMemberRequest.getEmail() == null || removeMemberRequest.getEmail().trim().isEmpty()) {
			baseResponse.setMessage("Invalid Email");
			baseResponse.setSuccess(false);
			return baseResponse;
		}

		if (removeMemberRequest.getProjectId() == null || removeMemberRequest.getProjectId().trim().isEmpty()) {
			baseResponse.setMessage("Invalid Project");
			baseResponse.setSuccess(false);
			return baseResponse;
		}

		UserProfile user = userRepo.findByEmailId(removeMemberRequest.getEmail());
		UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(user.getId());
		ProjectOrg projectOrg = projectOrgRepo.findByProjectId(removeMemberRequest.getProjectId());
		List<ProjectOrgRole> projectOrgRoleList = new ArrayList<>();
		if (removeMemberRequest.getRole() != null && !removeMemberRequest.getRole().isEmpty()) {
			Role role = roleRepo.findByRoleName(removeMemberRequest.getRole());
			ProjectOrgRole projectOrgRole = projectOrgRoleRepo.findByProjectOrgIdAndRoleId(projectOrg.getId(),
					role.getId());
			projectOrgRoleList.add(projectOrgRole);
		} else{
			projectOrgRoleList = projectOrgRoleRepo.findByProjectOrgId(projectOrg.getId());
		}


		List<String> projectOrgRoleIds = projectOrgRoleList.stream().map(p -> p.getId()).toList();


		if (userOrgRole.getProjectOrgRoleIdList() != null) {
			userOrgRole.getProjectOrgRoleIdList().removeIf(p -> projectOrgRoleIds.contains(p.getProjectOrganizationRoleId()));
		}

		String organizationId = projectOrg.getOrgId();

		Set<String> userOrgIds = userOrgRole.getProjectOrgRoleIdList()
				.stream()
				.map(p -> {
					Optional<ProjectOrgRole> projectOrgRole=projectOrgRoleRepo.findById(p.getProjectOrganizationRoleId());
					if(projectOrgRole.isEmpty()){
						LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,PROJECT_SERVICE_IMPL_CLASS,method,"ProjectOrgRole not found with this projectOrgRoleId {}",p,USERID,user.getId());
						throw new ProjectServiceException("ProjectOrgRole not found with this projectOrgRoleId "+p,HttpStatus.NOT_FOUND);
					}
					return projectOrgRole.get().getProjectOrgId();
				})
				.toList()
				.stream()
				.map(p -> {
					Optional<ProjectOrg> projectorg=projectOrgRepo.findById(p);
					if(projectorg.isEmpty()){
						LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,PROJECT_SERVICE_IMPL_CLASS,method,"ProjectOrg not found with this projectOrgId ",p,USERID,user.getId());
						throw new ProjectServiceException("ProjectOrg not found with this projectOrgId "+p,HttpStatus.NOT_FOUND);
					}
					return projectorg.get().getOrgId();
				})
				.collect(Collectors.toSet());

		if(!userOrgIds.contains(organizationId)) {
			String organizationWatcherRoleId = roleRepo.findByRoleName(PermissionConstants.ORG_WATCHER).getId();
			String orgRoleWatcherId = orgRoleRepo.findByOrgIdAndRoleId(organizationId, organizationWatcherRoleId).getId();

			if(userOrgRole.getOrgRoleIdList().contains(orgRoleWatcherId)) {
				userOrgRole.getOrgRoleIdList().remove(orgRoleWatcherId);
			}

		}

		checkAndRemoveDefaultProject(request, organizationId, removeMemberRequest.getProjectId());

		userOrgRoleRepo.save(userOrgRole);

		baseResponse.setMessage("User removed");
		baseResponse.setSuccess(true);
		return baseResponse;
	}

	@Override
	public BaseResponse fetchUserProjects(HttpServletRequest request){
		BaseResponse baseResponse = new BaseResponse();
		List<Project> projects = new ArrayList<>();
		String token = requestUtil.extractJwtFromRequest(request);
		String username = requestUtil.usernameFromToken(token);
		UserProfile user = userRepo.findByUsername(username);
		UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(user.getId());
		List<ProjectOrgRoleId> projectOrgRoleIdList = userOrgRole.getProjectOrgRoleIdList();
		List<String> ids = new ArrayList<>();
		projectOrgRoleIdList.forEach(projectOrgRoleId-> ids.add(projectOrgRoleId.getProjectOrganizationRoleId()));
		for (String s : ids) {
			Optional<ProjectOrgRole> projectOrgRole = projectOrgRoleRepo.findById(s);
			if(projectOrgRole.isPresent()){
				Optional<ProjectOrg> projectOrg = projectOrgRepo.findById(projectOrgRole.get().getProjectOrgId());
				if (projectOrg.isPresent()) {
					Optional<Project> project = projectRepo.findById(projectOrg.get().getProjectId());
					if (project.isPresent()) {
						projects.add(project.get());
					}
				}
			}
		}
		baseResponse.setPayload(projects);
		baseResponse.setMessage("Fetched projects of users");
		baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.OK));
		baseResponse.setSuccess(true);
		return baseResponse;
	}

	@Override
	public BaseResponse setUserDefaultProject(HttpServletRequest request, String orgId, String projectId){
		String method = "setUserDefaultProject";
		BaseResponse baseResponse = new BaseResponse();
		List<String> projects = new ArrayList<>();
		List<String> organizations = new ArrayList<>();
		Optional<Organization> searchOrg = orgRepo.findById(orgId);
		if(searchOrg.isEmpty())
			return getBaseResponse(baseResponse, "Organization not found", HttpStatus.NOT_FOUND);
		String token = requestUtil.extractJwtFromRequest(request);
		String username = requestUtil.usernameFromToken(token);
		UserProfile user = userRepo.findByUsername(username);
		UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(user.getId());
		List<ProjectOrgRoleId> projectOrgRoleIdList = userOrgRole.getProjectOrgRoleIdList();
		//set the projects based on projects org role else throw exception
		setProjects(projectOrgRoleIdList, user, projects);

		List<String> orgRoleIdList = userOrgRole.getOrgRoleIdList();
		if (orgRoleIdList != null){
			setOrganisations(orgRoleIdList, organizations, method, user);
		}
		if (!organizations.contains(orgId))
			return getBaseResponse(baseResponse, "You don't have access to this Organization", HttpStatus.UNAUTHORIZED);
		Optional<Project> searchProject = projectRepo.findById(projectId);
		if(searchProject.isEmpty()) return getBaseResponse(baseResponse, "Project not found", HttpStatus.NOT_FOUND);
		if (!projects.contains(projectId))
			return getBaseResponse(baseResponse, "You don't have access to this project", HttpStatus.UNAUTHORIZED);
		List<ProjectOrg> projectOrgList = projectOrgRepo.findByOrgId(orgId);
		HashSet<String > projectIds = new HashSet<>();
		for (int i=0; i<projectOrgList.size(); i++){
			projectIds.add(projectOrgList.get(i).getProjectId());
		}
		if (!projectIds.contains(projectId))
			return getBaseResponse(baseResponse, "Project does not belong to this organization", HttpStatus.NOT_FOUND);
		UserProjectDefaults userProjectDefaults = userProjectDefaultsRepository.findByUserIdAndOrgId(user.getId(),orgId);
		if (userProjectDefaults == null){
			UserProjectDefaults newUserProjectDefaults = new UserProjectDefaults();
			newUserProjectDefaults.setUserId(user.getId());
			newUserProjectDefaults.setOrgId(orgId);
			newUserProjectDefaults.setProjectId(projectId);
			userProjectDefaultsRepository.save(newUserProjectDefaults);
		} else {
			userProjectDefaults.setProjectId(projectId);
			userProjectDefaultsRepository.save(userProjectDefaults);
		}
		baseResponse.setMessage("User Organization's project default set successfully!");
		baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.OK));
		baseResponse.setSuccess(true);
		return baseResponse;
	}

	private void setProjects(List<ProjectOrgRoleId> projectOrgRoleIdList, UserProfile user, List<String> projects) {
		for (int i = 0; i< projectOrgRoleIdList.size(); i++){
			String projectOrgRoleId = projectOrgRoleIdList.get(i).getProjectOrganizationRoleId();
			Optional<ProjectOrgRole> projectOrgRole = projectOrgRoleRepo.findById(projectOrgRoleId);
			if(projectOrgRole.isEmpty()){
				LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,PROJECT_SERVICE_IMPL_CLASS, "setProjects",PROJECT_ORG_ROLE_NOT_FOUND,projectOrgRoleId,USERID, user.getId());
				throw new ProjectServiceException(ASSIGNED_PROJECT_ORG_ROLE_NOT_FOUND.label,HttpStatus.NOT_FOUND);
			}
			Optional<ProjectOrg> projectOrg = projectOrgRepo.findById(projectOrgRole.get().getProjectOrgId());
			if ( projectOrg.isPresent() ){
				Optional<Project> project = projectRepo.findById(projectOrg.get().getProjectId());
				if (project.isPresent()){
					projects.add(project.get().getId());
				}else{
					LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,PROJECT_SERVICE_IMPL_CLASS, "setProjects","project not found with this projectId",projectOrg.get().getProjectId(),USERID, user.getId());
					throw new ProjectServiceException("project not found with this projectId "+projectOrg.get().getProjectId(),HttpStatus.NOT_FOUND);
				}
			}
		}
	}

	private void setOrganisations(List<String> orgRoleIdList, List<String> organizations, String method, UserProfile user) {
		for (String orgRoleId : orgRoleIdList) {
			OrganizationRole orgRole = orgRoleRepo.findByPrimaryId(orgRoleId);
			if (orgRole != null) {
				Optional<Organization> org = orgRepo.findById(orgRole.getOrgId());
				if (org.isPresent()) {
					organizations.add(org.get().getId());
				}else{
					LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,PROJECT_SERVICE_IMPL_CLASS, method,"org not found with this orgId",orgRole.getOrgId(),USERID, user.getId());
					throw new ProjectServiceException("org not found with this orgId "+orgRole.getOrgId(),HttpStatus.NOT_FOUND);
				}
			}
		}
	}

	private static BaseResponse getBaseResponse(BaseResponse baseResponse, String message, HttpStatus httpStatus) {
		baseResponse.setSuccess(false);
		baseResponse.setMessage(message);
		baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(httpStatus));
		return baseResponse;
	}

	@Override
	public BaseResponse fetchUserDefaultProject(HttpServletRequest httpServletRequest, String orgId) {
		BaseResponse baseResponse = new BaseResponse();
		List<Project> projects = new ArrayList<>();
		String token = requestUtil.extractJwtFromRequest(httpServletRequest);
		String username = requestUtil.usernameFromToken(token);
		UserProfile user = userRepo.findByUsername(username);
		UserProjectDefaults userProjectDefaults = userProjectDefaultsRepository.findByUserIdAndOrgId(user.getId(),orgId);
		if (userProjectDefaults == null) return getUserProjectDefaults(orgId, user, projects, baseResponse);
		else {
			Optional<Project> project = projectRepo.findById(userProjectDefaults.getProjectId());
			if(project.isPresent()) {
				userProjectDefaults.setProjectName(project.get().getName());
			}
			baseResponse.setPayload(userProjectDefaults);
			baseResponse.setMessage("Default project is set!");
			baseResponse.setSuccess(true);
			return baseResponse;
		}
	}

	private BaseResponse getUserProjectDefaults(String orgId, UserProfile user, List<Project> projects, BaseResponse baseResponse) {
		UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(user.getId());
		List<ProjectOrgRoleId> projectOrgRoleIdList = userOrgRole.getProjectOrgRoleIdList();
		for (int i = 0; i < projectOrgRoleIdList.size(); i++) {
			String projectOrgRoleId= projectOrgRoleIdList.get(i).getProjectOrganizationRoleId();
			Optional<ProjectOrgRole> projectOrgRole = projectOrgRoleRepo.findById(projectOrgRoleId);
			if(projectOrgRole.isEmpty()){
				LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,PROJECT_SERVICE_IMPL_CLASS, "getUserProjectDefaults",PROJECT_ORG_ROLE_NOT_FOUND,projectOrgRoleId,USERID, user.getId());
				throw new ProjectServiceException(ASSIGNED_PROJECT_ORG_ROLE_NOT_FOUND.label,HttpStatus.NOT_FOUND);
			}
			List<ProjectOrg> projectOrgList = projectOrgRepo.findByIdAndOrgId(projectOrgRole.get().getProjectOrgId(), orgId);
			for (int j=0;j<projectOrgList.size();j++){
				Optional<Project> project = projectRepo.findById(projectOrgList.get(j).getProjectId());
				if (project.isPresent()) {
					projects.add(project.get());
				}
			}
		}
		if (projects.size() > 1 || projects.isEmpty() ) {
			baseResponse.setMessage("Default project is not set.");
			baseResponse.setSuccess(true);
			return baseResponse;
		} else {
			UserProjectDefaults newUserProjectDefaults = new UserProjectDefaults();
			newUserProjectDefaults.setOrgId(orgId);
			newUserProjectDefaults.setProjectId(projects.get(0).getId());
			newUserProjectDefaults.setUserId(user.getId());
			userProjectDefaultsRepository.save(newUserProjectDefaults);
			newUserProjectDefaults.setProjectName(projects.get(0).getName());
			baseResponse.setPayload(newUserProjectDefaults);
			baseResponse.setMessage("Default project is set!");
			baseResponse.setSuccess(true);
			return baseResponse;
		}
	}

	@Override
	public BaseResponse removeUserDefaultProject(HttpServletRequest httpServletRequest, String orgId) {
		String method = "removeUserDefaultProject";
		BaseResponse baseResponse = new BaseResponse();
		String token = requestUtil.extractJwtFromRequest(httpServletRequest);
		String username = requestUtil.usernameFromToken(token);
		UserProfile user = userRepo.findByUsername(username);
		UserProjectDefaults userProjectDefaults = userProjectDefaultsRepository.findByUserIdAndOrgId(user.getId(), orgId);
		if (userProjectDefaults != null) {
			removeUserDefaultProject(orgId, user, method, baseResponse, userProjectDefaults);
		}
		baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.OK));
		baseResponse.setSuccess(true);
		baseResponse.setMessage("User default project setting removed!");
		return baseResponse;
	}

	private BaseResponse removeUserDefaultProject(String orgId, UserProfile user, String method, BaseResponse baseResponse, UserProjectDefaults userProjectDefaults) {
		List<Project> projects = new ArrayList<>();
		UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(user.getId());
		List<ProjectOrgRoleId> projectOrgRoleIdList = userOrgRole.getProjectOrgRoleIdList();
		for (int i = 0; i < projectOrgRoleIdList.size(); i++) {
			String projectOrgRoleId = projectOrgRoleIdList.get(i).getProjectOrganizationRoleId();
			Optional<ProjectOrgRole> projectOrgRole = projectOrgRoleRepo.findById(projectOrgRoleId);
			if(projectOrgRole.isEmpty()){
				LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,PROJECT_SERVICE_IMPL_CLASS, method,PROJECT_ORG_ROLE_NOT_FOUND,projectOrgRoleId,USERID, user.getId());
				throw new ProjectServiceException(ASSIGNED_PROJECT_ORG_ROLE_NOT_FOUND.label,HttpStatus.NOT_FOUND);
			}
			List<ProjectOrg> projectOrgList = projectOrgRepo.findByIdAndOrgId(projectOrgRole.get().getProjectOrgId(), orgId);
			for (int j=0;j<projectOrgList.size();j++){
				Optional<Project> project = projectRepo.findById(projectOrgList.get(j).getProjectId());
				if (project.isPresent()) {
					projects.add(project.get());
				}else{
					LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,PROJECT_SERVICE_IMPL_CLASS, method,"project not found with this project",projectOrgList.get(j).getProjectId(),USERID, user.getId());
					throw new ProjectServiceException("project not found with this project"+projectOrgList.get(j).getProjectId(),HttpStatus.NOT_FOUND);
				}
			}
		}
		if (projects.size() == 1 ) {
			baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.OK));
			baseResponse.setMessage("You have only one project in this organization, it cannot be removed from being default!");
			baseResponse.setSuccess(true);
			return  baseResponse;
		}
		userProjectDefaultsRepository.deleteById(userProjectDefaults.getId());
        return baseResponse;
    }

	public void checkAndRemoveDefaultProject(HttpServletRequest httpServletRequest, String orgId, String projectId){
		// Check if user removed from project, has this project as default.
		String token = requestUtil.extractJwtFromRequest(httpServletRequest);
		String username = requestUtil.usernameFromToken(token);
		UserProfile user = userRepo.findByUsername(username);
		UserProjectDefaults userProjectDefaults = userProjectDefaultsRepository.findByUserIdAndOrgId(user.getId(), orgId);
		if (userProjectDefaults != null && userProjectDefaults.getProjectId().equalsIgnoreCase(projectId)) {
			userProjectDefaultsRepository.deleteById(userProjectDefaults.getId());
		}
	}
}
