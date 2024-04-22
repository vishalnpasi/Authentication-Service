package com.albanero.authservice.service.impl;

import com.albanero.authservice.common.constants.HttpHeaderConstants;
import com.albanero.authservice.common.constants.PermissionConstants;
import com.albanero.authservice.common.dto.ProjectOrgRoleId;
import com.albanero.authservice.common.dto.request.*;
import com.albanero.authservice.common.dto.response.*;
import com.albanero.authservice.common.util.HelperUtil;
import com.albanero.authservice.common.util.RequestUtil;
import com.albanero.authservice.exception.UserRoleServiceException;
import com.albanero.authservice.exception.UserServiceException;
import com.albanero.authservice.model.Permissions;
import com.albanero.authservice.model.*;
import com.albanero.authservice.repository.*;
import com.albanero.authservice.service.UserRoleService;
import com.albanero.authservice.service.impl.rolepermissions.ModulesPermissionsHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URISyntaxException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.albanero.authservice.common.constants.CommonLoggingConstants.*;
import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.ACTION_FAILED_EXCEPTION;
import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO;
import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG;
import static com.albanero.authservice.common.constants.ResponseMessageConstants.VALID_API_ROLE_MAPPING;

@Service
@RefreshScope
public class UserRoleServiceImpl implements UserRoleService {
    private static final Logger LOGGER = LoggerFactory.getLogger(UserRoleServiceImpl.class);

    private static final String USER_ROLE_SERVICE_IMPL = "UserRoleServiceImpl";
    public static final String SET_PROJECT_LEVEL_DETAILS = "setProjectLevelDetails";

    private final UserRepository userRepo;

    private final OrgRepository orgRepo;

    private final RoleRepository roleRepo;

    private final UserOrgRoleRepository userOrgRoleRepo;

    private final PermissionsRepository permissionsRepo;

    private final OrgRoleRepository orgRoleRepo;

    private final ProjectRepository projectRepo;

    private final ProjectOrgRepository projectOrgRepo;

    private final ProjectOrgRoleRepository projectOrgRoleRepo;

    private final PlatformApiDetailsRepository platformApiDetailsRepo;

    private final OrgRoleRepository orgRoleRepository;

    private final AccStatusRepository accStatusRepo;

    private final RequestUtil requestUtil;

    private final ModuleRepository moduleRepository;

    private final SubModuleRepository subModuleRepository;

    private final ModulesPermissionsHelper modulesPermissionsHelper;

    @Autowired
    public UserRoleServiceImpl(UserRepository userRepo, OrgRepository orgRepo, RoleRepository roleRepo, UserOrgRoleRepository userOrgRoleRepo, PermissionsRepository permissionsRepo, OrgRoleRepository orgRoleRepo, ProjectRepository projectRepo, ProjectOrgRepository projectOrgRepo, ProjectOrgRoleRepository projectOrgRoleRepo, PlatformApiDetailsRepository platformApiDetailsRepo, OrgRoleRepository orgRoleRepository, AccStatusRepository accStatusRepo, RequestUtil requestUtil, ModuleRepository moduleRepository, SubModuleRepository subModuleRepository, ModulesPermissionsHelper modulesPermissionsHelper) {
        this.userRepo = userRepo;
        this.orgRepo = orgRepo;
        this.roleRepo = roleRepo;
        this.userOrgRoleRepo = userOrgRoleRepo;
        this.permissionsRepo = permissionsRepo;
        this.orgRoleRepo = orgRoleRepo;
        this.projectRepo = projectRepo;
        this.projectOrgRepo = projectOrgRepo;
        this.projectOrgRoleRepo = projectOrgRoleRepo;
        this.platformApiDetailsRepo = platformApiDetailsRepo;
        this.orgRoleRepository = orgRoleRepository;
        this.accStatusRepo = accStatusRepo;
        this.requestUtil = requestUtil;
        this.moduleRepository = moduleRepository;
        this.subModuleRepository = subModuleRepository;
        this.modulesPermissionsHelper = modulesPermissionsHelper;
    }

    @Override
    public void setUserIdDetails(UserProfile userProfile, UserIdDetails userIdDetails) {
        UserProfileDetails userProfileDetails = setUserProfileDetails(userProfile);
        userIdDetails.setUserProfileDetails(userProfileDetails);
    }

    @Override
    public UserIdDetails fetchUserIdDetails(UserOrgRole userOrgRole, AuthRequest authRequest, UserProfile userProfile) {
        String method = "fetchUserIdDetails";
        UserIdDetails userIdDetails = new UserIdDetails();
        OrgLevelDetails orgLevelDetails = authRequest.getOrgDetails();
        ProjectLevelDetails projectLevelDetails = authRequest.getProjectLevelDetails();

        if (userOrgRole.getPlatformRoleIdList() != null && orgLevelDetails == null && projectLevelDetails == null) {
            setPlatformRoleDetails(userOrgRole, method, userIdDetails);
        }

        if (userOrgRole.getOrgRoleIdList() != null && orgLevelDetails != null) {
            setOrgLevelDetails(userOrgRole, orgLevelDetails, userIdDetails);

        }

        if (userOrgRole.getProjectOrgRoleIdList() != null && orgLevelDetails != null) {
            setProjectLevelDetails(userOrgRole, orgLevelDetails, userIdDetails);
        }

        UserProfileDetails userProfileDetails = setUserProfileDetails(userProfile);
        userIdDetails.setUserProfileDetails(userProfileDetails);
        return userIdDetails;
    }

    private void setPermissions(Role role,HttpStatus notFound, List<String> permissions) {
        for (String permissionId : role.getPermissionIdList()) {
            Optional<Permissions> permission = permissionsRepo.findById(permissionId);
            if (permission.isEmpty()) {
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, "setPermissions", PERMISSION_NOT_FOUND, permissionId);
                throw new UserRoleServiceException(PERMISSION_NOT_FOUND + permissionId, notFound);
            }
            permissions.add(permission.get().getPermission());
        }
    }

    private void setOrgLevelDetails(UserOrgRole userOrgRole, OrgLevelDetails orgLevelDetails, UserIdDetails userIdDetails) {

            List<OrgLevelDetails> orgLevelDetailsList = new ArrayList<>();
            Organization org = null;
            if (orgLevelDetails.getOrgId() != null) {
                Optional<Organization> orgOpt = orgRepo.findById(orgLevelDetails.getOrgId());
                if (orgOpt.isEmpty()) {
                    LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, "setOrgLevelDetails", ORGANIZATION_NOT_FOUND, orgLevelDetails.getOrgId());
                    throw new UserRoleServiceException(ORGANIZATION_NOT_FOUND + orgLevelDetails.getOrgId(), HttpStatus.NOT_FOUND);
                }
                org = orgOpt.get();
            } else {
                org = orgRepo.findByOrgUrl(orgLevelDetails.getOrgUrl());
            }

            List<OrganizationRole> organizationRoleList = orgRoleRepo.findByOrgId(org.getId());
            for (OrganizationRole orgRole : organizationRoleList) {
                if (userOrgRole.getOrgRoleIdList().contains(orgRole.getId())) {
                    Optional<Role> role = roleRepo.findById(orgRole.getRoleId());
                    if (role.isEmpty()) {
                        LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, "setOrgLevelDetails", ROLE_NOT_FOUND, orgRole.getRoleId());
                        throw new UserRoleServiceException(ROLE_NOT_FOUND + orgRole.getRoleId(), HttpStatus.NOT_FOUND);
                    }
                    String roleName = role.get().getRoleName();
                    List<String> permissions = new ArrayList<>();
                    //setPermissions
                    setPermissions(role.get(), HttpStatus.NOT_FOUND, permissions);

                    orgLevelDetails = new OrgLevelDetails();
                    orgLevelDetails.setOrgName(org.getName());
                    orgLevelDetails.setOrgUrl(org.getOrgUrl());
                    orgLevelDetails.setOrgId(org.getId());
                    orgLevelDetails.setRole(roleName);
                    orgLevelDetails.setRoleId(role.get().getId());
                    orgLevelDetails.setRolePermissions(permissions);
                    orgLevelDetailsList.add(orgLevelDetails);

                }
            }
            userIdDetails.setOrgLevelDetails(orgLevelDetailsList);
        }


    private void setProjectLevelDetails(UserOrgRole userOrgRole, OrgLevelDetails orgLevelDetails, UserIdDetails userIdDetails) {
        Organization org = null;
        if (orgLevelDetails.getOrgId() != null) {
            Optional<Organization> orgOpt = orgRepo.findById(orgLevelDetails.getOrgId());
            if (orgOpt.isEmpty()) {
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, SET_PROJECT_LEVEL_DETAILS, ORGANIZATION_NOT_FOUND, orgLevelDetails.getOrgId());
                throw new UserRoleServiceException(ORGANIZATION_NOT_FOUND + orgLevelDetails.getOrgId(), HttpStatus.NOT_FOUND);
            }
            org = orgOpt.get();
        } else
            org = orgRepo.findByOrgUrl(orgLevelDetails.getOrgUrl());

        List<ProjectLevelDetails> projectLevelDetailsList = new ArrayList<>();

        List<ProjectOrg> projectOrgList = projectOrgRepo.findByOrgId(org.getId());
        HashMap<String, List<String>> projectOrgsHashMap = new HashMap<>();
        for (ProjectOrg projectOrg : projectOrgList) {
            List<ProjectOrgRole> projectOrgRoleList = projectOrgRoleRepo.findByProjectOrgId(projectOrg.getId());
            for (ProjectOrgRole projectOrgRole : projectOrgRoleList) {
                List<String> ids = new ArrayList<>();
                userOrgRole.getProjectOrgRoleIdList().forEach(projectOrgRoleId -> ids.add(projectOrgRoleId.getProjectOrganizationRoleId()));
                if (ids.contains(projectOrgRole.getId())) {
                    List<String> projectOrgIds = projectOrgsHashMap.get(projectOrg.getProjectId()) != null ? projectOrgsHashMap.get(projectOrg.getProjectId()) : new ArrayList<>();
                    projectOrgIds.add(projectOrgRole.getId());
                    projectOrgsHashMap.put(projectOrg.getProjectId(), projectOrgIds);
                }
            }
        }
        setProjectLevelDetails( userIdDetails, projectOrgsHashMap, org, projectLevelDetailsList);
    }

    private void setProjectLevelDetails( UserIdDetails userIdDetails, HashMap<String, List<String>> projectOrgsHashMap, Organization org, List<ProjectLevelDetails> projectLevelDetailsList) {
        ProjectLevelDetails projectLevelDetails;
        for (Map.Entry<String, List<String>> entry : projectOrgsHashMap.entrySet()) {
            String key = entry.getKey();
            List<String> projectOrgIds = entry.getValue();
            projectLevelDetails = new ProjectLevelDetails();
            for (String projectOrgId : projectOrgIds) {
                Optional<ProjectOrgRole> projectOrgRole = projectOrgRoleRepo.findById(projectOrgId);
                if (projectOrgRole.isEmpty()) {
                    LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, SET_PROJECT_LEVEL_DETAILS, PROJECT_ORG_ROLE_NOT_FOUND, projectOrgId);
                    throw new UserRoleServiceException(PROJECT_ORG_ROLE_NOT_FOUND + projectOrgId, HttpStatus.NOT_FOUND);
                }
                Optional<Role> projectRole = roleRepo.findById(projectOrgRole.get().getRoleId());
                if (projectRole.isEmpty()) {
                    LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, SET_PROJECT_LEVEL_DETAILS, ROLE_NOT_FOUND, projectOrgRole.get().getRoleId());
                    throw new UserRoleServiceException(ROLE_NOT_FOUND + projectOrgRole.get().getRoleId(), HttpStatus.NOT_FOUND);
                }
                Optional<Project> project = projectRepo.findById(key);
                if (project.isEmpty()) {
                    LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, SET_PROJECT_LEVEL_DETAILS, PROJECT_NOT_FOUND, key);
                    throw new UserRoleServiceException(PROJECT_NOT_FOUND + key, HttpStatus.NOT_FOUND);
                }
                String projectName = project.get().getName();
                List<String> projectPermissions = new ArrayList<>();
                projectLevelDetails.setProjectName(projectName);
                projectLevelDetails.setProjectId(project.get().getId());
                projectLevelDetails.setOrgName(org.getName());
                projectLevelDetails.setOrgId(org.getId());
                List<RolePermissionDetails> userRoles = projectLevelDetails.getUserRoles() != null ? projectLevelDetails.getUserRoles() : new ArrayList<>();
                RolePermissionDetails rolePermissionDetails = new RolePermissionDetails();
                rolePermissionDetails.setRole(projectRole.get().getRoleName());
                rolePermissionDetails.setRoleId(projectRole.get().getId());
                userRoles.add(rolePermissionDetails);
                projectLevelDetails.setUserRoles(userRoles);
                projectLevelDetails.setRolePermissions(projectPermissions);
            }
            projectLevelDetailsList.add(projectLevelDetails);
        }
        userIdDetails.setProjectLevelDetails(projectLevelDetailsList);
    }

    private void setPlatformRoleDetails(UserOrgRole userOrgRole, String method, UserIdDetails userIdDetails) {
        List<RolePermissionDetails> rolePermissionDetailsList = new ArrayList<>();
        for (String roleId : userOrgRole.getPlatformRoleIdList()) {
            Optional<Role> role = roleRepo.findById(roleId);
            if (role.isEmpty()) {
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, method, ROLE_NOT_FOUND, roleId);
                throw new UserRoleServiceException(ROLE_NOT_FOUND + roleId, HttpStatus.NOT_FOUND);
            }
            String roleName = role.get().getRoleName();
            List<String> permissions = new ArrayList<>();
            setPermissions(role.get(), HttpStatus.INTERNAL_SERVER_ERROR, permissions);
            RolePermissionDetails rolePermissionDetails = new RolePermissionDetails();
            rolePermissionDetails.setRole(roleName);
            rolePermissionDetails.setRoleId(role.get().getId());
            rolePermissionDetails.setRolePermissions(permissions);
            rolePermissionDetailsList.add(rolePermissionDetails);
        }
        userIdDetails.setPlatformRoleDetails(rolePermissionDetailsList);
    }

    public UserProfileDetails setUserProfileDetails(UserProfile userProfile) {
        AccountStatus accountStatus = accStatusRepo.findByUserId(userProfile.getId());
        UserProfileDetails userProfileDetails = new UserProfileDetails();
        userProfileDetails.setEmailId(userProfile.getEmailId());
        userProfileDetails.setUserId(userProfile.getId());
        userProfileDetails.setUsername(userProfile.getUsername());
        userProfileDetails.setFullName(userProfile.getFirstName() + " " + userProfile.getLastName());
        userProfileDetails.setId(userProfile.getId());
        userProfileDetails.setProfileImageDetails(userProfile.getProfileImageDetails());
        userProfileDetails.setIsAccountApproved(accountStatus.getAccountApprovalStatus() != null ? accountStatus.getAccountApprovalStatus().getIsAccountApproved() : Boolean.FALSE);
        userProfileDetails.setIsAccountActive(accountStatus.getAccountActivationStatus() != null ? accountStatus.getAccountActivationStatus().getIsActive() : Boolean.FALSE);

        return userProfileDetails;
    }

    public UserProfileDetails setUserProfileDetailsWithoutImg(UserProfile userProfile) {
        AccountStatus accountStatus = accStatusRepo.findByUserId(userProfile.getId());
        UserProfileDetails userProfileDetails = new UserProfileDetails();
        userProfileDetails.setEmailId(userProfile.getEmailId());
        userProfileDetails.setUserId(userProfile.getId());
        userProfileDetails.setUsername(userProfile.getUsername());
        userProfileDetails.setFullName(userProfile.getFirstName() + " " + userProfile.getLastName());
        userProfileDetails.setId(userProfile.getId());
        userProfileDetails.setIsAccountApproved(accountStatus.getAccountApprovalStatus() != null ? accountStatus.getAccountApprovalStatus().getIsAccountApproved() : Boolean.FALSE);
        userProfileDetails.setIsAccountActive(accountStatus.getAccountActivationStatus() != null ? accountStatus.getAccountActivationStatus().getIsActive() : Boolean.FALSE);

        return userProfileDetails;
    }

    @Override
    public BaseResponse getUserMappings(HttpServletRequest request, AuthRequest authRequest) {
        BaseResponse baseResponse = new BaseResponse();
        long startTime = System.currentTimeMillis();
        try {
            String token = requestUtil.extractJwtFromRequest(request);
            String username = requestUtil.usernameFromToken(token);
            UserProfile userProfile = userRepo.findByUsername(username);
            UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(userProfile.getId());

            if (userOrgRole != null) {
                UserIdDetails userIdDetails = fetchUserIdDetails(userOrgRole, authRequest, userProfile);
                baseResponse.setSuccess(true);
                baseResponse.setMessage("Successfully fetched User Mappings");
                baseResponse.setPayload(userIdDetails);
                LOGGER.info("Time taken by AuthService::getUserMappings {}", (System.currentTimeMillis() - startTime));
                return baseResponse;
            }
            baseResponse.setMessage("Given user does not have a valid role");
            baseResponse.setSuccess(false);
            LOGGER.error("Given user does not have a valid role in AuthService::getUserMappings");
            return baseResponse;

        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_ROLE_SERVICE_IMPL, "getUserMappings", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage(ACTION_FAILED_EXCEPTION.label);
            baseResponse.setSuccess(false);
            return baseResponse;
        }
    }

    @Override
    public BaseResponse validateUserMappings(UserIdDetails userIdDetails, UserProfile userProfile) {
        BaseResponse baseResponse = new BaseResponse();
        AuthTokenResponse authTokenResponse = new AuthTokenResponse();

        authTokenResponse.setIsTokenValid(true);
        authTokenResponse.setUserId(userProfile.getId());
        authTokenResponse.setUsername(userProfile.getUsername());
        authTokenResponse.setFirstName(userProfile.getFirstName());
        authTokenResponse.setLastName(userProfile.getLastName());
        authTokenResponse.setEmailId(userProfile.getEmailId());
        baseResponse.setMessage("Authentication token is valid.");
        baseResponse.setSuccess(true);
        baseResponse.setPayload(authTokenResponse);
        return baseResponse;
    }

    @Override
    public DefaultRolePermissions setDefaultRolePermissions(Role role) {
        List<String> listOfPermissions = new ArrayList<>();
        DefaultRolePermissions defaultRolePermissions = new DefaultRolePermissions();
        defaultRolePermissions.setRole(role.getRoleName());
        defaultRolePermissions.setDescription(role.getDescription());
        List<String> permissionIdList = role.getPermissionIdList();

        for (String permissionId : permissionIdList) {
            Optional<Permissions> permission = permissionsRepo.findById(permissionId);
            if (permission.isEmpty()) {
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, "setDefaultRolePermissions", PERMISSION_NOT_FOUND, permissionId);
                throw new UserRoleServiceException(PERMISSION_NOT_FOUND + permissionId, HttpStatus.NOT_FOUND);
            }
            listOfPermissions.add(permission.get().getDescription());
        }

        defaultRolePermissions.setRolePermissions(listOfPermissions);
        return defaultRolePermissions;
    }

    @Override
    public BaseResponse authorizeApiRoutes(HttpServletRequest request, ApiDetails apiDetails) {
        BaseResponse baseResponse = new BaseResponse();
        if (apiDetails.getOrgDetails().getOrgId() == null || apiDetails.getProjectLevelDetails().getProjectId() == null
                || apiDetails.getApiMethod() == null || apiDetails.getApiRoute() == null) {
            baseResponse.setMessage("Bad Request");
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.BAD_REQUEST));
            baseResponse.setSuccess(false);
            return baseResponse;
        }

        String token = requestUtil.extractJwtFromRequest(request);
        String username = requestUtil.usernameFromToken(token);
        UserProfile userProfile = userRepo.findByUsername(username);
        UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(userProfile.getId());


        if (userOrgRole != null) {
            BaseResponse baseResponse1 = authorizeApiRoutesIfUserOrgRoleExists(apiDetails, userOrgRole, baseResponse);
            if (baseResponse1 != null) return baseResponse1;
        }

        baseResponse.setMessage("Access Denied");
        baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
        baseResponse.setSuccess(false);
        return baseResponse;
    }

    private BaseResponse authorizeApiRoutesIfUserOrgRoleExists(ApiDetails apiDetails, UserOrgRole userOrgRole, BaseResponse baseResponse) {
        Optional<Organization> org;
        if (userOrgRole.getOrgRoleIdList() != null && apiDetails.getOrgDetails() != null) {
            org = orgRepo.findById(apiDetails.getOrgDetails().getOrgId());
            if (org.isEmpty()) {
                baseResponse.setMessage("Org not found with this orgId " + apiDetails.getOrgDetails().getOrgId());
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
                baseResponse.setSuccess(false);
                return baseResponse;
            }

            List<OrganizationRole> orgRoleList = orgRoleRepo.findByOrgId(org.get().getId());

            for (OrganizationRole orgRole : orgRoleList) {
                Optional<Role> role = roleRepo.findById(orgRole.getRoleId());
                if (role.isPresent() && (userOrgRole.getOrgRoleIdList().contains(orgRole.getId()) && (role.get().getRoleName().equals(PermissionConstants.ORG_ADMIN) || role.get().getRoleName().equals(PermissionConstants.ROOT_USER)))) {
                    baseResponse.setMessage(VALID_API_ROLE_MAPPING.toString());
                    baseResponse.setSuccess(true);
                    return baseResponse;
                }
            }
        }

        if (userOrgRole.getProjectOrgRoleIdList() != null && apiDetails.getOrgDetails() != null
                && apiDetails.getProjectLevelDetails() != null) {
            BaseResponse baseResponse2 = getAuthorizeApiRoutes(apiDetails, userOrgRole, baseResponse);
            if (baseResponse2 != null) return baseResponse2;
        }
        return null;
    }

    private BaseResponse getAuthorizeApiRoutes(ApiDetails apiDetails, UserOrgRole userOrgRole, BaseResponse baseResponse) {
        Optional<Project> project = projectRepo.findById(apiDetails.getProjectLevelDetails().getProjectId());
        if (project.isEmpty()) {
            baseResponse.setMessage("Access Denied");
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
            baseResponse.setSuccess(false);
            return baseResponse;
        }

        //check user have default role for current project
        ProjectOrgRoleId deaultProjectOrgRoleId = getDefaultProjectOrgRole(userOrgRole, apiDetails);

        Optional<ProjectOrgRole> projectOrgRole = projectOrgRoleRepo.findById(deaultProjectOrgRoleId.getProjectOrganizationRoleId());

        if (projectOrgRole.isEmpty()) {
            LOGGER.error("ProjectOrgRole(Line508) not found with this {} projectOrgRole.", deaultProjectOrgRoleId.getProjectOrganizationRoleId());
            throw new UserServiceException(ACTION_FAILED_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        Optional<Role> role = roleRepo.findById(projectOrgRole.get().getRoleId());
        if (role.isPresent()) {
            BaseResponse baseResponse1 = validateApiRoutesIfRoleExists(apiDetails, role.get(), baseResponse);
            if (baseResponse1 != null) return baseResponse1;
        } else{
            LOGGER.error("Role(Line472) not found with this {} RoleId.", projectOrgRole.get().getRoleId());
            throw new UserServiceException(ACTION_FAILED_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return null;
    }

    private BaseResponse validateApiRoutesIfRoleExists(ApiDetails apiDetails, Role role, BaseResponse baseResponse) {
        if (role.getRoleName().equals(PermissionConstants.PROJECT_ADMIN)) {
            baseResponse.setMessage(VALID_API_ROLE_MAPPING.toString());
            baseResponse.setSuccess(true);
            return baseResponse;
        } else {
            List<String> permissionIdList = role.getPermissionIdList();
            BaseResponse baseResponse1 = getAuthroizeApiroutesBasedOnPermissions(apiDetails, baseResponse, permissionIdList);
            if (baseResponse1 != null) return baseResponse1;
        }
        return null;
    }

    private BaseResponse getAuthroizeApiroutesBasedOnPermissions(ApiDetails apiDetails, BaseResponse baseResponse, List<String> permissionIdList) {
        for (String permissionId : permissionIdList) {
            Optional<Permissions> permissions = permissionsRepo.findById(permissionId);
            if (permissions.isPresent()) {
                List<String> allowedEndPoints = permissions.get().getAllowedEndpointIdList();
                List<PlatformApiDetails> platformApiDetails = new ArrayList<>();

                setPlatformApiDetails(allowedEndPoints, platformApiDetails);

                for (PlatformApiDetails platformApiDetail : platformApiDetails) {
                    Pattern pattern = Pattern.compile(platformApiDetail.getApiRoute());
                    Matcher matcher = pattern.matcher(apiDetails.getApiRoute());

                    if (matcher.find() && apiDetails.getApiMethod().equals(platformApiDetail.getApiMethod())) {
                        baseResponse.setMessage(VALID_API_ROLE_MAPPING.toString());
                        baseResponse.setSuccess(true);
                        return baseResponse;
                    }
                }
            }
            LOGGER.error("Permission(Line481) not found with this {} permissionId.", permissionId);
        }
        return null;
    }

    private void setPlatformApiDetails(List<String> allowedEndPoints, List<PlatformApiDetails> platformApiDetails) {
        for (String allowedEndPoint : allowedEndPoints) {
            Optional<PlatformApiDetails> platformApiDetail = platformApiDetailsRepo.findById(allowedEndPoint);
            if (platformApiDetail.isPresent()) {
                platformApiDetails.add(platformApiDetail.get());
            }
        }
    }

    private ProjectOrgRoleId getDefaultProjectOrgRole(UserOrgRole userOrgRole, ApiDetails apiDetails) {
        ProjectOrg projectOrg = projectOrgRepo.findByProjectIdAndOrgId(apiDetails.getProjectLevelDetails().getProjectId(), apiDetails.getOrgDetails().getOrgId());
        if (Objects.isNull(projectOrg)) {
            throw new UserServiceException("Project Org Info doesn't exist.", HttpStatus.NOT_FOUND);
        }

        String projectOrgId = projectOrg.getId();
        List<ProjectOrgRole> projectOrgRole = projectOrgRoleRepo.findByProjectOrgId(projectOrgId);
        if (projectOrgRole.isEmpty()) {
            throw new UserServiceException("Project org details not found.", HttpStatus.NOT_FOUND);
        }

        for (ProjectOrgRoleId projectOrgRoleIdFromList : userOrgRole.getProjectOrgRoleIdList()) {
            String projectOrgRoleId = "";
            for (ProjectOrgRole projectOrgRole1 : projectOrgRole) {
                projectOrgRoleId = projectOrgRole1.getId();
                if (Objects.equals(projectOrgRoleIdFromList.getProjectOrganizationRoleId(), projectOrgRoleId) && Objects.equals(projectOrgRoleIdFromList.getIsDefault(), true)) {
                    return projectOrgRoleIdFromList;
                }
            }
        }
        throw new UserServiceException("No default project role is configured, please configure project role.", HttpStatus.NOT_FOUND);
    }

    //Only for Authentication Service:-
    public Boolean authorizeIamRoutes(HttpServletRequest request, UserProfile userProfile) throws URISyntaxException {
        String method = "authorizeIamRoutes";
        try {
            String endPoint = request.getRequestURI();
            String endPointMethod = request.getMethod();

            String originName = request.getHeader(HttpHeaders.ORIGIN);
            Organization org = new Organization();
            boolean orgPresent = false;

            org = getOrganization(request, orgPresent, org, originName);
            if (org == null) return true;

            UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(userProfile.getId());

            if (userOrgRole != null) {
                return validateIamRoutesBasedOnUserOrgRole(request, userProfile, userOrgRole, endPoint, endPointMethod, org);

            }
            return false;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_ROLE_SERVICE_IMPL, method, e.getMessage(), e.getStackTrace());
            return false;
        }
    }

    private Boolean validateIamRoutesBasedOnUserOrgRole(HttpServletRequest request, UserProfile userProfile, UserOrgRole userOrgRole, String endPoint, String endPointMethod, Organization org) {
        if (validateIamRoutesBasedOnPlatformRoles(userProfile, userOrgRole, endPoint, endPointMethod)) return true;
        if (userOrgRole.getOrgRoleIdList() != null) {
            if (org.getId() == null) {
                return false;
            }
            List<OrganizationRole> orgRoleList = orgRoleRepo.findByOrgId(org.getId());

            if (validateIamRoutesBasedOnOrgRoleApiDetails(userProfile, orgRoleList, userOrgRole, endPoint, endPointMethod)){
                return true;
            }
        }
        if (request.getHeader(HttpHeaderConstants.X_PROJECT_ID) != null && userOrgRole.getProjectOrgRoleIdList() != null) {
            String projectId = request.getHeader("x-project-id");
            Optional<Project> project = projectRepo.findById(projectId);
            if (project.isEmpty()) {
                return false;
            }

            ProjectOrg projectOrg = projectOrgRepo.findByProjectIdAndOrgId(projectId, org.getId());

            List<ProjectOrgRole> projectOrgRoleList = projectOrgRoleRepo.findByProjectOrgId(projectOrg.getId());

            for (ProjectOrgRole projectOrgRole : projectOrgRoleList) {
                if (validateIamRoutesBasedOnProjectOrgRole(userProfile, projectOrgRole, userOrgRole, "validateIamRoutesBasedOnUserOrgRole", endPoint, endPointMethod))
                    return true;
            }
        }
        return false;
    }

    private boolean validateIamRoutesBasedOnPlatformRoles(UserProfile userProfile, UserOrgRole userOrgRole, String endPoint, String endPointMethod) {
        if (userOrgRole.getPlatformRoleIdList() != null) {
            List<String> platformRoleIds = userOrgRole.getPlatformRoleIdList();
            for (String platformRoleId : platformRoleIds) {
                Optional<Role> platformRole = roleRepo.findById(platformRoleId);
                if (platformRole.isEmpty()) {
                    LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, "validateIamRoutesBasedOnPlatformRoles", "platformRole not found with this platformRoleId", platformRoleId, USERID, userProfile.getId());
                    throw new UserRoleServiceException("platformRole not found with this platformRoleId " + platformRoleId, HttpStatus.NOT_FOUND);
                }
                List<String> permissionIdList = platformRole.get().getPermissionIdList();
                if (validateIamRoutesBasedPermissionList(endPoint, endPointMethod, permissionIdList))
                    return true;
            }
        }
        return false;
    }

    private boolean validateIamRoutesBasedOnOrgRoleApiDetails(UserProfile userProfile, List<OrganizationRole> orgRoleList, UserOrgRole userOrgRole, String endPoint, String endPointMethod) {
        for (OrganizationRole orgRole : orgRoleList) {
            Optional<Role> role = roleRepo.findById(orgRole.getRoleId());
            if (userOrgRole.getOrgRoleIdList().contains(orgRole.getId())) {
                if (role.isEmpty()) {
                    LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, "validateIamRoutesBasedOnOrgRoleApiDetails", ROLE_NOT_FOUND, orgRole.getRoleId(), USERID, userProfile.getId());
                    throw new UserRoleServiceException(ROLE_NOT_FOUND + orgRole.getRoleId(), HttpStatus.NOT_FOUND);
                }
                List<String> permissionIdList = role.get().getPermissionIdList();
                if (validateIamRoutesBasedPermissionList(endPoint, endPointMethod, permissionIdList)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean validateIamRoutesBasedPermissionList(String endPoint, String endPointMethod, List<String> permissionIdList) {
        for (String permissionId : permissionIdList) {
            Optional<Permissions> permissions = permissionsRepo.findById(permissionId);
            if (permissions.isPresent()) {
                List<String> allowedEndPoints = permissions.get().getAllowedEndpointIdList();
                List<PlatformApiDetails> platformApiDetailsArrayList = new ArrayList<>();

                if (allowedEndPoints != null && validateIamRoutesIfAllowedEndpointsNotNull(endPoint, endPointMethod, allowedEndPoints, platformApiDetailsArrayList)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean validateIamRoutesIfAllowedEndpointsNotNull(String endPoint, String endPointMethod, List<String> allowedEndPoints, List<PlatformApiDetails> platformApiDetailsArrayList) {
        setPlatformApiDetails(allowedEndPoints, platformApiDetailsArrayList);

        for (PlatformApiDetails platformApiDetail : platformApiDetailsArrayList) {
            Pattern pattern = Pattern.compile(platformApiDetail.getApiRoute());
            Matcher matcher = pattern.matcher(endPoint);

            if (matcher.find() && endPointMethod.equals(platformApiDetail.getApiMethod())) {
                return true;
            }
        }
        return false;
    }

    private boolean validateIamRoutesBasedOnProjectOrgRole(UserProfile userProfile, ProjectOrgRole projectOrgRole, UserOrgRole userOrgRole, String method, String endPoint, String endPointMethod) {
        Optional<Role> role = roleRepo.findById(projectOrgRole.getRoleId());

        List<String> ids = new ArrayList<>();
        userOrgRole.getProjectOrgRoleIdList().forEach(projectOrgRoleId -> ids.add(projectOrgRoleId.getProjectOrganizationRoleId()));
        if (ids.contains(projectOrgRole.getId())) {
            if (role.isEmpty()) {
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, method, ROLE_NOT_FOUND, projectOrgRole.getRoleId(), USERID, userProfile.getId());
                throw new UserRoleServiceException(ROLE_NOT_FOUND + projectOrgRole.getRoleId(), HttpStatus.INTERNAL_SERVER_ERROR);
            }
            List<String> permissionIdList = role.get().getPermissionIdList();
            for (String permissionId : permissionIdList) {
                Optional<Permissions> permissions = permissionsRepo.findById(permissionId);
                if (permissions.isEmpty()) {
                    LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, method, PERMISSION_NOT_FOUND, permissionId, USERID, userProfile.getId());
                    throw new UserRoleServiceException(PERMISSION_NOT_FOUND + permissionId, HttpStatus.INTERNAL_SERVER_ERROR);
                }
                List<String> allowedEndPoints = permissions.get().getAllowedEndpointIdList();
                List<PlatformApiDetails> platformApiDetailsArrayList = new ArrayList<>();

                if (allowedEndPoints != null && validateIamRoutesIfAllowedEndpointsNotNull(endPoint, endPointMethod, allowedEndPoints, platformApiDetailsArrayList))
                        return true;
            }
        }
        return false;
    }

    private Organization getOrganization(HttpServletRequest request, boolean orgPresent, Organization org, String originName) {
        String orgUrl;
        if (request.getHeader(HttpHeaderConstants.X_ORG_ID) != null && !request.getHeader(HttpHeaderConstants.X_ORG_ID).isEmpty()) {
            String orgId = request.getHeader(HttpHeaderConstants.X_ORG_ID);
            Optional<Organization> orgOpt = orgRepo.findById(orgId);
            if (orgOpt.isPresent()) {
                orgPresent = true;
                org = orgOpt.get();
            }
        }
        if (!orgPresent) {
            if ((originName != null && !originName.isEmpty())) {
                orgUrl = originName.substring(8);
                org = orgRepo.findByOrgUrl(orgUrl);
            } else {
                return null;
            }
        }
        return org;
    }

    @Override
    public BaseResponse updateUserRolesInProject(HttpServletRequest request, UserProfileDetails userProfileDetails) {
        String method = "updateUserRolesInProject";
        BaseResponse baseResponse = new BaseResponse();
        if (userProfileDetails.getEmailId() == null || userProfileDetails.getEmailId().trim().isEmpty()) {
            baseResponse.setMessage("Invalid Email");
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.BAD_REQUEST));
            return baseResponse;
        }

        if (userProfileDetails.getProjectId() == null || userProfileDetails.getProjectId().trim().isEmpty()) {
            baseResponse.setMessage("Invalid Project");
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.BAD_REQUEST));
            return baseResponse;
        }

        UserProfile user = userRepo.findByEmailId(userProfileDetails.getEmailId());
        UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(user.getId());
        ProjectOrg projectOrg = projectOrgRepo.findByProjectId(userProfileDetails.getProjectId());

        List<ProjectOrgRoleId> userProjectOrgRoleIdList = userOrgRole.getProjectOrgRoleIdList();

        ArrayList<ProjectOrgRoleId> projectOrgRoleIdList = new ArrayList<>();

        validateProjectOrgRoleAndRole(userProjectOrgRoleIdList, method, user);

        BaseResponse baseResponse1 = setProjectOrgRoleIdList(userProfileDetails, projectOrg, user, baseResponse, userOrgRole, projectOrgRoleIdList);
        if (baseResponse1 != null) return baseResponse1;


        if (userProjectOrgRoleIdList != null) {
            userOrgRole.getProjectOrgRoleIdList().addAll(projectOrgRoleIdList);
        } else {
            userOrgRole.setProjectOrgRoleIdList(projectOrgRoleIdList);
        }

        userOrgRoleRepo.save(userOrgRole);

        baseResponse.setMessage("User roles updated");
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    private void validateProjectOrgRoleAndRole(List<ProjectOrgRoleId> userProjectOrgRoleIdList, String method, UserProfile user) {
        if (userProjectOrgRoleIdList != null) {
            for (ProjectOrgRoleId userProjectRoleId : userProjectOrgRoleIdList) {
                Optional<ProjectOrgRole> projectOrgRole = projectOrgRoleRepo.findById(userProjectRoleId.getProjectOrganizationRoleId());
                if (projectOrgRole.isEmpty()) {
                    LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, method, PROJECT_ORG_ROLE_NOT_FOUND, userProjectRoleId, USERID, user.getId());
                    throw new UserRoleServiceException(PROJECT_ORG_ROLE_NOT_FOUND + userProjectRoleId.getProjectOrganizationRoleId(), HttpStatus.NOT_FOUND);
                }
                Optional<Role> role = roleRepo.findById(projectOrgRole.get().getRoleId());
                validateRole(projectOrgRole.get(), role, method, user);

            }
        }
    }

    private BaseResponse setProjectOrgRoleIdList(UserProfileDetails userProfileDetails, ProjectOrg projectOrg, UserProfile user, BaseResponse baseResponse, UserOrgRole userOrgRole, ArrayList<ProjectOrgRoleId> projectOrgRoleIdList) {
        for (String roleName : userProfileDetails.getUserRoles()) {
                Role role = roleRepo.findByRoleName(roleName);
                ProjectOrgRole projectOrgRole = projectOrgRoleRepo.findByProjectOrgIdAndRoleId(projectOrg.getId(),
                        role.getId());
                if (Objects.isNull(projectOrgRole)) {
                    RoleType roleType = role.getRoleType();
                    Optional<Project> project = projectRepo.findById(userProfileDetails.getProjectId());
                    if (project.isEmpty()) {
                        LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, "setProjectOrgRoleIdList", PROJECT_NOT_FOUND, userProfileDetails.getProjectId(), USERID, user.getId());
                        throw new UserRoleServiceException(PROJECT_NOT_FOUND + userProfileDetails.getProjectId(), HttpStatus.NOT_FOUND);
                    }
                    if (roleType.getRoleTypeName().equals(PermissionConstants.PROJECT_DEFAULT) || roleType.getProjectId().contains(project.get().getId())) {
                        projectOrgRole = new ProjectOrgRole();
                        projectOrgRole.setProjectOrgId(projectOrg.getId());
                        projectOrgRole.setRoleId(role.getId());
                        projectOrgRoleRepo.save(projectOrgRole);
                    } else {
                        baseResponse.setMessage("Given role is not associated to the project");
                        baseResponse.setSuccess(false);
                        return baseResponse;
                    }
                }
                List<String> ids = new ArrayList<>();
                userOrgRole.getProjectOrgRoleIdList().forEach(projectOrgRoleId -> ids.add(projectOrgRoleId.getProjectOrganizationRoleId()));
                if (!ids.contains(projectOrgRole.getId())) {
                    projectOrgRoleIdList.add(new ProjectOrgRoleId(projectOrgRole.getId(), false));
                }
        }
        return null;
    }

    @Override
    public BaseResponse updateUserRolesInOrg(HttpServletRequest request, UserProfileDetails userProfileDetails) {
        String method = "updateUserRolesInOrg";
        BaseResponse baseResponse = new BaseResponse();
        if (userProfileDetails.getEmailId() == null || userProfileDetails.getEmailId().trim().isEmpty()) {
            baseResponse.setMessage("Invalid Email");
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.BAD_REQUEST));
            return baseResponse;
        }

        if (userProfileDetails.getOrgId() == null || userProfileDetails.getOrgId().trim().isEmpty()) {
            baseResponse.setMessage("Invalid Organisation");
            baseResponse.setSuccess(false);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.BAD_REQUEST));
            return baseResponse;
        }

        UserProfile user = userRepo.findByEmailId(userProfileDetails.getEmailId());
        UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(user.getId());

        boolean isAdmin = false;
        ArrayList<String> orgRoleIdList = new ArrayList<>();

        //This loop to check for exsisting admin role for that organization
        BaseResponse baseResponse1 = isUserOrgAdmin(userProfileDetails, userOrgRole, method, user, baseResponse);
        if (baseResponse1 != null) return baseResponse1;

        //this is to check if incomming roles has organization admin role thhen handle curent roles
        for (String roleName : userProfileDetails.getUserRoles()) {
            if (roleName.equals(PermissionConstants.ORG_ADMIN)) {
                isAdmin = true;
            } else {
                Role role = roleRepo.findByRoleName(roleName);
                OrganizationRole orgRole = orgRoleRepo.findByOrgIdAndRoleId(userProfileDetails.getOrgId(), role.getId());
                if (!userOrgRole.getOrgRoleIdList().contains(orgRole.getId())) {
                    orgRoleIdList.add(orgRole.getId());
                }
            }
        }

        updateUserOrgRolesIfAdmin(userProfileDetails, isAdmin, orgRoleIdList, userOrgRole);

        userOrgRole.getOrgRoleIdList().addAll(orgRoleIdList);
        userOrgRoleRepo.save(userOrgRole);

        baseResponse.setMessage("User roles updated");
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    private BaseResponse isUserOrgAdmin(UserProfileDetails userProfileDetails, UserOrgRole userOrgRole, String method, UserProfile user, BaseResponse baseResponse) {
        for (String userOrgRoleId : userOrgRole.getOrgRoleIdList()) {
            Optional<OrganizationRole> organizationRole = orgRoleRepo.findById(userOrgRoleId);
            if (organizationRole.isEmpty()) {
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, method, "OrganizationRole not found with this organizationRoleId", userOrgRoleId, USERID, user.getId());
                throw new UserRoleServiceException("OrganizationRole not found with this organizationRoleId " + userOrgRoleId, HttpStatus.NOT_FOUND);
            }
            Optional<Role> role = roleRepo.findById(organizationRole.get().getRoleId());
            if (role.isEmpty()) {
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, method, ROLE_NOT_FOUND, organizationRole.get().getRoleId(), USERID, user.getId());
                throw new UserRoleServiceException(ROLE_NOT_FOUND + organizationRole.get().getRoleId(), HttpStatus.NOT_FOUND);
            }
            if (organizationRole.get().getOrgId().equals(userProfileDetails.getOrgId()) && role.get().getRoleName().equals(PermissionConstants.ORG_ADMIN)) {

                baseResponse.setMessage("User is the admin of the organization.");
                baseResponse.setSuccess(false);
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.BAD_REQUEST));
                return baseResponse;

            }
        }
        return null;
    }

    private void updateUserOrgRolesIfAdmin(UserProfileDetails userProfileDetails, boolean isAdmin, ArrayList<String> orgRoleIdList, UserOrgRole userOrgRole) {
        //this condition to remove all the roles for that user within that organization and add admin role or add new roles
        if (Boolean.TRUE.equals(isAdmin)) {
            Role role = roleRepo.findByRoleName(PermissionConstants.ORG_ADMIN);
            List<OrganizationRole> orgRoleList = orgRoleRepo.findByOrgId(userProfileDetails.getOrgId());
            OrganizationRole orgAdminRole = orgRoleRepo.findByOrgIdAndRoleId(userProfileDetails.getOrgId(), role.getId());

            orgRoleIdList.clear();
            orgRoleIdList.add(orgAdminRole.getId());

            for (OrganizationRole orgRole : orgRoleList) {
                userOrgRole.getOrgRoleIdList().remove(orgRole.getId());
            }
        }
    }

    public BaseResponse syncRolesToProjectOrg() {
        BaseResponse baseResponse = new BaseResponse();
        List<ProjectOrg> projectOrgs = projectOrgRepo.findAll();

        for (ProjectOrg projectOrg : projectOrgs) {
            ProjectOrgRole projectOrgRole = new ProjectOrgRole();
            projectOrgRole.setProjectOrgId(projectOrg.getId());
            projectOrgRole.setRoleId("62eb75f68cea8c13e1bfa0e0");
            projectOrgRoleRepo.save(projectOrgRole);
        }

        return baseResponse;
    }

    @Override
    public BaseResponse addRolesToUsers() {
        BaseResponse baseResponse = new BaseResponse();
        List<Organization> organizations = orgRepo.findAll();
        for (Organization organization : organizations) {
            OrganizationRole orgRole = new OrganizationRole();
            OrganizationRole orgAdminRole = orgRoleRepo.findByOrgIdAndRoleId(organization.getId(), "62f3af5e7d4bcb4d748b7668");
            if (orgAdminRole == null) {
                orgRole.setOrgId(organization.getId());
                orgRole.setRoleId("62e2a59888fb4d1c4403cef5");
                orgRoleRepository.save(orgRole);
            }
        }
        return baseResponse;
    }

    @Override
    public BaseResponse addOrgWatcherToUsers() {
        BaseResponse baseResponse = new BaseResponse();
        try {

            // removing commented code lead to removing all logic from here, if needed, go back in git history

            baseResponse.setMessage("org watcher role added");
            baseResponse.setSuccess(true);
            return baseResponse;
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, USER_ROLE_SERVICE_IMPL, "addOrgWatcherToUsers", e.getMessage(), e.getStackTrace());
            baseResponse.setMessage("org watcher role not added.");
            baseResponse.setSuccess(false);
            return baseResponse;
        }
    }

    @Override
    public List<ModuleNameDto> userRolePermissions(HttpServletRequest request) {
        String method = "userRolePermissions";
        String token = requestUtil.extractJwtFromRequest(request);
        String username = requestUtil.usernameFromToken(token);
        UserProfile userProfile = userRepo.findByUsername(username);
        UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(userProfile.getId());
        String orgId = request.getHeader(HttpHeaderConstants.X_ORG_ID);
        String projectId = request.getHeader(HttpHeaderConstants.X_PROJECT_ID);
        List<ModuleNameDto> permissionTree;
        HashSet<String> submoduleIdList = new HashSet<>();
        HashSet<String> moduleIdList = new HashSet<>();
        List<String> permissionIdsList = new ArrayList<>();
        boolean isProjectAdmin = false;
        boolean isOrgAdmin = false;
        isOrgAdmin = isOrgAdmin(orgId, userOrgRole, isOrgAdmin);

        if (projectId != null && userOrgRole.getProjectOrgRoleIdList() != null) {
            ProjectOrg projectOrg = projectOrgRepo.findByProjectIdAndOrgId(projectId, orgId);
            List<ProjectOrgRole> projectOrgRoleList = projectOrgRoleRepo.findByProjectOrgId(projectOrg.getId());
            for (ProjectOrgRole projectOrgRole : projectOrgRoleList) {
                Optional<Role> role = roleRepo.findById(projectOrgRole.getRoleId());
                List<String> ids = new ArrayList<>();
                userOrgRole.getProjectOrgRoleIdList().forEach(projectOrgRoleId -> ids.add(projectOrgRoleId.getProjectOrganizationRoleId()));
                if (ids.contains(projectOrgRole.getId())) {
                    validateRole(projectOrgRole, role, method, userProfile);
                    isProjectAdmin = role.get().getRoleName().equals(PermissionConstants.PROJECT_ADMIN);
                    List<String> permissionIdList;
                    permissionIdList = role.get().getPermissionIdList();
                    permissionIdsList.addAll(permissionIdList);
                    setModulesBasedOnPermissions(permissionIdList, submoduleIdList, moduleIdList, userProfile);
                }
            }
        }

        Boolean isAdmin = isOrgAdmin || isProjectAdmin;
        permissionTree = modulesPermissionsHelper.permissionTreeFromModules(moduleIdList, submoduleIdList, permissionIdsList, isAdmin);
        return permissionTree;
    }

    private void setModulesBasedOnPermissions(List<String> permissionIdList, HashSet<String> submoduleIdList, HashSet<String> moduleIdList,UserProfile userProfile) {
        for (String permissionId : permissionIdList) {
            Optional<Permissions> permission = permissionsRepo.findById(permissionId);
            if (permission.isPresent()) {

                setModuleIdList(permission.get(), submoduleIdList, moduleIdList);
                setModules(permission.get(), moduleIdList);

            } else {
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, "setModulesBasedOnPermissions", PERMISSION_NOT_FOUND, permissionId, USERID, userProfile.getId());
                throw new UserRoleServiceException(PERMISSION_NOT_FOUND + permissionId, HttpStatus.NOT_FOUND);
            }
        }
    }

    private void setModuleIdList(Permissions permission, HashSet<String> submoduleIdList, HashSet<String> moduleIdList) {
        if (permission.getSubModuleId() != null) {
            Boolean subModuleIsPresent = subModuleRepository.findById(permission.getSubModuleId()).isPresent();
            if (Boolean.TRUE.equals(subModuleIsPresent)) {
                Optional<SubModules> subModules = subModuleRepository.findById(permission.getSubModuleId());
                if (subModules.isPresent()) {
                    submoduleIdList.add(subModules.get().getId());
                    Optional<Modules> modules = moduleRepository.findById(subModules.get().getModuleId());
                    if (modules.isPresent()) {
                        moduleIdList.add(modules.get().getId());
                    }
                }

            }
        }
    }

    private void setModules(Permissions permission, HashSet<String> moduleIdList) {
        if (permission.getModuleId() != null) {
            Optional<Modules> modules = moduleRepository.findById(permission.getModuleId());
            if (modules.isPresent()) {
                moduleIdList.add(modules.get().getId());
            }
        }
    }

    private static void validateRole(ProjectOrgRole projectOrgRole, Optional<Role> role, String method, UserProfile userProfile) {
        if (role.isEmpty()) {
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, method, ROLE_NOT_FOUND, projectOrgRole.getRoleId(), USERID, userProfile.getId());
            throw new UserRoleServiceException(ROLE_NOT_FOUND + projectOrgRole.getRoleId(), HttpStatus.NOT_FOUND);
        }
    }

    private boolean isOrgAdmin(String orgId, UserOrgRole userOrgRole, boolean isOrgAdmin) {
        if (orgId != null) {
            List<OrganizationRole> orgRoleList = orgRoleRepo.findByOrgId(orgId);
            for (OrganizationRole orgRole : orgRoleList) {
                Optional<Role> role = roleRepo.findById(orgRole.getRoleId());
                if (role.isPresent() && userOrgRole.getOrgRoleIdList().contains(orgRole.getId())) {
                    isOrgAdmin = role.get().getRoleName().equals(PermissionConstants.ORG_ADMIN);
                }
            }
        }
        return isOrgAdmin;
    }

    public BaseResponse checkUserAccessForOrgAndProjects(List<String> projectOrgRoleIdList, UserOrgRole userOrgRole, String orgId, String projectId) {
        String method = "checkUserAccessForOrgAndProjects";
        List<String> projects = new ArrayList<>();
        List<String> organizations = new ArrayList<>();
        BaseResponse baseResponse = new BaseResponse();
        setProjects(projectOrgRoleIdList, method, projects);
        List<String> orgRoleIdList = userOrgRole.getOrgRoleIdList();
        setOrganizations(orgRoleIdList, organizations, method);
        if (!organizations.contains(orgId)) {
            baseResponse.setSuccess(false);
            baseResponse.setMessage("You don't have access to this Organization");
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
            return baseResponse;
        }
        Optional<Project> searchProject = projectRepo.findById(projectId);
        if (searchProject.isEmpty()) {
            baseResponse.setSuccess(false);
            baseResponse.setMessage("Project not found");
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.NOT_FOUND));
            return baseResponse;
        }
        if (!projects.contains(projectId)) {
            baseResponse.setSuccess(false);
            baseResponse.setMessage("You don't have access to this project");
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.UNAUTHORIZED));
            return baseResponse;
        }
        List<ProjectOrg> projectOrgList = projectOrgRepo.findByOrgId(orgId);
        HashSet<String> projectIds = new HashSet<>();
        for (int i = 0; i < projectOrgList.size(); i++) {
            projectIds.add(projectOrgList.get(i).getProjectId());
        }
        if (!projectIds.contains(projectId)) {
            baseResponse.setSuccess(false);
            baseResponse.setMessage("Project does not belong to this organization");
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.NOT_FOUND));
            return baseResponse;
        }
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    private void setOrganizations(List<String> orgRoleIdList, List<String> organizations, String method) {
        if (orgRoleIdList != null) {
            for (String orgRoleId : orgRoleIdList) {
                OrganizationRole orgRole = orgRoleRepo.findByPrimaryId(orgRoleId);
                if (orgRole != null) {
                    Optional<Organization> org = orgRepo.findById(orgRole.getOrgId());
                    if (org.isPresent()) {
                        organizations.add(org.get().getId());
                    } else {
                        LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, method, ORGANIZATION_NOT_FOUND, orgRole.getOrgId());
                        throw new UserRoleServiceException(ORGANIZATION_NOT_FOUND + orgRole.getOrgId(), HttpStatus.NOT_FOUND);
                    }
                }
            }
        }
    }

    private void setProjects(List<String> projectOrgRoleIdList, String method, List<String> projects) {
        for (int i = 0; i < projectOrgRoleIdList.size(); i++) {
            String projectOrgRoleId = projectOrgRoleIdList.get(i);
            Optional<ProjectOrgRole> projectOrgRole = projectOrgRoleRepo.findById(projectOrgRoleId);
            if (projectOrgRole.isEmpty()) {
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, method, PROJECT_ORG_ROLE_NOT_FOUND, projectOrgRoleId);
                throw new UserRoleServiceException(PROJECT_ORG_ROLE_NOT_FOUND + projectOrgRoleId, HttpStatus.NOT_FOUND);
            }
            Optional<ProjectOrg> projectOrg = projectOrgRepo.findById(projectOrgRole.get().getProjectOrgId());
            if (projectOrg.isPresent()) {
                Optional<Project> project = projectRepo.findById(projectOrg.get().getProjectId());
                if (project.isPresent()) {
                    projects.add(project.get().getId());
                } else {
                    LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, method, PROJECT_NOT_FOUND, projectOrg.get().getProjectId());
                    throw new UserRoleServiceException(PROJECT_NOT_FOUND + projectOrg.get().getProjectId(), HttpStatus.NOT_FOUND);
                }
            } else {
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, USER_ROLE_SERVICE_IMPL, method, "ProjectOrg not found with this projectOrgId", projectOrgRole.get().getProjectOrgId());
                throw new UserRoleServiceException("ProjectOrg not found with this projectOrgId " + projectOrgRole.get().getProjectOrgId(), HttpStatus.NOT_FOUND);
            }
        }
    }
}