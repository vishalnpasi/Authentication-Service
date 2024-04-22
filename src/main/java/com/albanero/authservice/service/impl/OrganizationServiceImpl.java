package com.albanero.authservice.service.impl;

import com.albanero.authservice.common.constants.HttpHeaderConstants;
import com.albanero.authservice.common.constants.OrganizationMessageConstants;
import com.albanero.authservice.common.constants.PermissionConstants;
import com.albanero.authservice.common.dto.ProjectOrgRoleId;
import com.albanero.authservice.common.dto.request.*;
import com.albanero.authservice.common.dto.response.*;
import com.albanero.authservice.common.util.EmailUtil;
import com.albanero.authservice.common.util.HelperUtil;
import com.albanero.authservice.common.util.RequestUtil;
import com.albanero.authservice.exception.OrganizationServiceException;
import com.albanero.authservice.model.*;
import com.albanero.authservice.repository.*;
import com.albanero.authservice.service.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jasypt.util.text.BasicTextEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;

import java.io.UnsupportedEncodingException;
import java.util.*;
import java.util.stream.Collectors;

import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.ACTION_FAILED_EXCEPTION;
import static com.albanero.authservice.common.constants.LoggerConstants.*;

@Service
public class OrganizationServiceImpl implements OrganizationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(OrganizationServiceImpl.class);

    public static final String ROLE_ADMIN = "ROLE_ADMIN";

    private static final String ORGANIZATION_SERVICE_IMPL_CLASS = "OrganizationServiceImpl";

    public static final Long USER_VERIFICATION_TOKEN_DURATION = 3 * 24 * 60 * 60000L;
    public static final String SET_USER_PROFILE_DETAILS = "setUserProfileDetails";

    @Value("${jasyptSecret}")
    private String encryptorPassword;
    private final AuthenticationService authService;

    private final OrgRepository orgRepo;

    private final UserRepository userRepo;

    private final RoleRepository roleRepo;

    private final OrgRoleRepository orgRoleRepo;

    private final UserOrgRoleRepository userOrgRoleRepo;

    private final ProductRepository productRepo;

    private final AccStatusRepository accStatusRepo;

    private final UserRoleService userRoleService;

    private final ProjectOrgRepository projectOrgRepo;

    private final ProjectRepository projectRepo;

    private final ProjectOrgRoleRepository projectOrgRoleRepo;

    private final HelperUtil helperUtil;

    private final RequestUtil requestUtil;

    private final EmailUtil emailUtil;

    private final RBAService rbaService;

    private final TokenService tokenService;


    @Autowired
    public OrganizationServiceImpl(RoleRepository roleRepo, OrgRoleRepository orgRoleRepo,
                                   UserOrgRoleRepository userOrgRoleRepo, ProductRepository productRepo,
                                   AccStatusRepository accStatusRepo, UserRoleService userRoleService,
                                   ProjectOrgRepository projectOrgRepo, ProjectRepository projectRepo,
                                   ProjectOrgRoleRepository projectOrgRoleRepo, HelperUtil helperUtil,
                                   RequestUtil requestUtil, EmailUtil emailUtil, RBAService rbaService,
                                   TokenService tokenService, UserRepository userRepo,
                                   AuthenticationService authService, OrgRepository orgRepo) {
        this.roleRepo = roleRepo;
        this.orgRoleRepo = orgRoleRepo;
        this.userOrgRoleRepo = userOrgRoleRepo;
        this.productRepo = productRepo;
        this.accStatusRepo = accStatusRepo;
        this.userRoleService = userRoleService;
        this.projectOrgRepo = projectOrgRepo;
        this.projectRepo = projectRepo;
        this.projectOrgRoleRepo = projectOrgRoleRepo;
        this.helperUtil = helperUtil;
        this.requestUtil = requestUtil;
        this.emailUtil = emailUtil;
        this.rbaService = rbaService;
        this.tokenService = tokenService;
        this.userRepo = userRepo;
        this.authService = authService;
        this.orgRepo = orgRepo;
    }

    @Override
    public BaseResponse createOrganization(HttpServletRequest request, OrgLevelDetails orgDetails) {
        BaseResponse baseResponse = new BaseResponse();
        String token = requestUtil.extractJwtFromRequest(request);
        String username = requestUtil.usernameFromToken(token);
        UserProfile user = userRepo.findByUsername(username);

        UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(user.getId());
        Role rootUserRole = roleRepo.findByRoleName(PermissionConstants.ROOT_USER);
        if (userOrgRole != null && userOrgRole.getPlatformRoleIdList() != null
                && userOrgRole.getPlatformRoleIdList().contains(rootUserRole.getId())) {
            validateOrgdetails(orgDetails);
            Organization org = new Organization();

            org.setName(orgDetails.getOrgName());
            org.setOrgUrl(orgDetails.getOrgUrl());
            org.setProductIdList(orgDetails.getProductIdList());
            orgRepo.save(org);

            List<Role> orgDefaultRoles = roleRepo.findByOrganizationDefaultRoleType();
            for (Role orgDefaultRole : orgDefaultRoles) {
                OrganizationRole orgRole = new OrganizationRole();
                orgRole.setRoleId(orgDefaultRole.getId());
                orgRole.setOrgId(org.getId());
                orgRoleRepo.save(orgRole);
                if (orgDefaultRole.getRoleName().equals(PermissionConstants.ORG_ADMIN)) {
                    List<String> orgRoleIdList;
                    orgRoleIdList = userOrgRole.getOrgRoleIdList() != null ? userOrgRole.getOrgRoleIdList()
                            : new ArrayList<>();
                    orgRoleIdList.add(orgRole.getId());
                    userOrgRole.setOrgRoleIdList(orgRoleIdList);
                    userOrgRole.setUserId(user.getId());
                    userOrgRoleRepo.save(userOrgRole);
                }
            }

            baseResponse.setMessage(String.valueOf(OrganizationMessageConstants.ORGANIZATION_CREATION_SUCCESSFUL));
            baseResponse.setSuccess(true);
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.OK));
            return baseResponse;
        }
        throw new OrganizationServiceException(OrganizationMessageConstants.INVALID_ROLE_TO_CREATE_ORGANIZATION, HttpStatus.FORBIDDEN);
    }

    private void validateOrgdetails(OrgLevelDetails orgDetails) {
        if (orgDetails == null || orgDetails.getOrgUrl() == null || orgDetails.getOrgName() == null
                || orgDetails.getProductIdList() == null) {
            throw new OrganizationServiceException(OrganizationMessageConstants.INCOMPLETE_ORGANIZATION_DETAILS, HttpStatus.BAD_REQUEST);
        }
        Role orgAdminRole = roleRepo.findByRoleAndRoleType(PermissionConstants.ORG_ADMIN, PermissionConstants.ORGANIZATION_DEFAULT);

        if (orgAdminRole == null) {
            throw new OrganizationServiceException(OrganizationMessageConstants.ORG_ADMIN_ROLE_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
        if (!helperUtil.isValidOrganizationName(orgDetails.getOrgName())) {
            throw new OrganizationServiceException(OrganizationMessageConstants.ORG_NAME_NOT_VALID, HttpStatus.UNPROCESSABLE_ENTITY);
        }
        if (!helperUtil.isValidOrganizationUrl(orgDetails.getOrgUrl())) {
            throw new OrganizationServiceException(OrganizationMessageConstants.ORG_URL_NOT_VALID, HttpStatus.UNPROCESSABLE_ENTITY);
        }
        if (helperUtil.checkForDuplicateOrgName(orgDetails.getOrgName())
                || helperUtil.checkForDuplicateOrgUrl(orgDetails.getOrgUrl())) {
            throw new OrganizationServiceException(OrganizationMessageConstants.DUPLICATE_ORGANIZATION, HttpStatus.UNPROCESSABLE_ENTITY);
        }
        if (!isValidProductList(orgDetails.getProductIdList())) {
            throw new OrganizationServiceException(OrganizationMessageConstants.VALID_PRODUCT_ID, HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    private boolean isValidProductList(List<String> productIdList) {
        List<Product> listOfProducts = productRepo.findAll();
        if (!listOfProducts.isEmpty()) {
            List<String> listOfProductIds = new ArrayList<>();
            for (Product product : listOfProducts)
                listOfProductIds.add(product.getId());
            for (String id : productIdList) {
                if (!listOfProductIds.contains(id))
                    return false;
            }
            return true;
        }
        return false;
    }

    @Override
    public BaseResponse updateOrganization(HttpServletRequest request, OrgLevelDetails orgDetails) {
        BaseResponse baseResponse = new BaseResponse();
        Organization org = orgRepo.findByOrgUrl(orgDetails.getOrgUrl());
        if (org == null) {
            throw new OrganizationServiceException(OrganizationMessageConstants.ORGANIZATION_NOT_FOUND, HttpStatus.NOT_FOUND);
        }

        if (orgDetails.getOrgName() != null && helperUtil.checkForOtherDuplicateOrgName(orgDetails.getOrgName(), org.getId())) {
            throw new OrganizationServiceException(OrganizationMessageConstants.DUPLICATE_ORGANIZATION, HttpStatus.BAD_REQUEST);
        }

        if (orgDetails.getAdminEmail() != null && !orgDetails.getAdminEmail().isEmpty() && !helperUtil.isValidEmail(orgDetails.getAdminEmail())) {
            throw new OrganizationServiceException(OrganizationMessageConstants.INVALID_ADMIN_EMAIL, HttpStatus.BAD_REQUEST);
        }

        if (orgDetails.getAlbaneroEmail() != null && !orgDetails.getAlbaneroEmail().isEmpty() && !helperUtil.isValidEmail(orgDetails.getAlbaneroEmail())) {
            throw new OrganizationServiceException(OrganizationMessageConstants.INVALID_EMAIL, HttpStatus.BAD_REQUEST);
        }

        org.setName(orgDetails.getOrgName());
        org.setAdminEmail(orgDetails.getAdminEmail());
        org.setAdminName(orgDetails.getAdminName());
        org.setAlbaneroEmail(orgDetails.getAlbaneroEmail());
        orgRepo.save(org);
        baseResponse.setMessage("Successfully updated the Organization!");
        baseResponse.setSuccess(true);
        return baseResponse;

    }

    @Override
    public BaseResponse verifyOrg(HttpServletRequest request, OrgLevelDetails orgDetails) {
        String method = "verifyOrg";
        BaseResponse baseResponse = new BaseResponse();
        ObjectMapper mapper = new ObjectMapper();
        String token = requestUtil.extractJwtFromRequest(request);
        if (token == null) {
            //verify organisation if token is not present or null
            return verifyOrgIfTokenNull(orgDetails, baseResponse);
        }

        //validate token
        validateToken(token);

        BaseResponse userIdDetailsResponse = requestUtil.getUserMappings(token);
        UserIdDetails userIdDetails = mapper.convertValue(userIdDetailsResponse.getPayload(), UserIdDetails.class);
        String username = userIdDetails.getUserProfileDetails().getUsername();
        UserProfile dbuser = authService.loadUserProfileByUsername(username);


        CurrentContext currentContext = new CurrentContext();
        //setting currentContext if organisation details are present
        setCurrentContextIfOrgIdPresent(request, currentContext);
        //setting currentContext if project details are present
        setCurrentContextIfProjectIdPresent(request, currentContext);
        userIdDetails.setCurrentContext(currentContext);

        UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(dbuser.getId());

        if (userOrgRole != null) {
            String orgId = request.getHeader(HttpHeaderConstants.X_ORG_ID);

            String projectId = request.getHeader(HttpHeaderConstants.X_PROJECT_ID);

            List<ModuleNameDto> userPermissionTree = new ArrayList<>();
            if (orgId != null && !orgId.isEmpty() && projectId != null && !projectId.isEmpty()) {
                Boolean isOrgPresent = orgRepo.findById(orgId).isPresent();

                Boolean isProjectPresent = projectRepo.findById(projectId).isPresent();

                if (isOrgPresent && isProjectPresent) {
                    userPermissionTree = userRoleService.userRolePermissions(request);
                }
            }
            userIdDetails.setUserPermissionTree(userPermissionTree);
            List<String> orgRoleIdList = userOrgRole.getOrgRoleIdList();
            List<ProjectOrgRoleId> projectOrgRoleIds = userOrgRole.getProjectOrgRoleIdList();
            List<String> projectOrgRoleIdList = new ArrayList<>();
            projectOrgRoleIds.forEach(projectOrgRoleId -> projectOrgRoleIdList.add(projectOrgRoleId.getProjectOrganizationRoleId()));
            List<String> platformRoleIdList = userOrgRole.getPlatformRoleIdList();
            List<Product> productDetails = new ArrayList<>();
            if (platformRoleIdList != null) {
                //verify organisation details based on platform role id list
                return verifyOrgBasedOnPlatoformRoleIdList(orgDetails, productDetails, userIdDetails, baseResponse);
            }
            if (orgRoleIdList != null) {
                //verify organisation details based on org role id list
                return verifyOrgBasedOnOrgRoleIdList(orgDetails, orgRoleIdList, productDetails, userIdDetails, baseResponse);

            }
            if (!projectOrgRoleIdList.isEmpty()) {
                //verify organisation details based on project org role id list
                return verifyOrgBasedOnProjectOrgRoleIdList(orgDetails, projectOrgRoleIdList, productDetails, userIdDetails, baseResponse);
            }
        }
        LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG, ORGANIZATION_SERVICE_IMPL_CLASS, method, "Invalid Organization ", "orgUrl", orgDetails.getOrgUrl());
        throw new OrganizationServiceException(OrganizationMessageConstants.INVALID_ORG, HttpStatus.BAD_REQUEST);

    }

    private BaseResponse verifyOrgBasedOnPlatoformRoleIdList(OrgLevelDetails orgDetails, List<Product> productDetails, UserIdDetails userIdDetails, BaseResponse baseResponse) {
        Organization org = orgRepo.findByOrgUrl(orgDetails.getOrgUrl());
        List<String> productIdList = org.getProductIdList();
        if (productIdList != null && !productIdList.isEmpty()) {
            for (String productId : productIdList) {
                Optional<Product> product = productRepo.findById(productId);
                if (product.isPresent()) {
                    productDetails.add(product.get());
                }
            }
            userIdDetails.setProductDetails(productDetails);
        }
        baseResponse.setPayload(userIdDetails);
        baseResponse.setMessage(String.valueOf(OrganizationMessageConstants.VALID_ORGANIZATION));
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    private BaseResponse verifyOrgBasedOnProjectOrgRoleIdList(OrgLevelDetails orgDetails, List<String> projectOrgRoleIdList, List<Product> productDetails, UserIdDetails userIdDetails, BaseResponse baseResponse) {
        Organization org = orgRepo.findByOrgUrl(orgDetails.getOrgUrl());
        List<ProjectOrg> projectOrgList = projectOrgRepo.findByOrgId(org.getId());
        for (ProjectOrg projectOrg : projectOrgList) {
            List<ProjectOrgRole> projectOrgRoleList = projectOrgRoleRepo.findByProjectOrgId(projectOrg.getId());
            for (ProjectOrgRole projectOrgRole : projectOrgRoleList) {
                if (projectOrgRoleIdList.contains(projectOrgRole.getId())) {
                    return setProductDetails(productDetails, userIdDetails, baseResponse, org);
                }
            }
        }
        LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG, ORGANIZATION_SERVICE_IMPL_CLASS, "verifyOrgBasedOnProjectOrgRoleIdList", "Could not validate organization or fetch product details! ", "orgUrl", orgDetails.getOrgUrl());
        throw new OrganizationServiceException(OrganizationMessageConstants.COULD_NOT_VALIDATE_ORG, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private BaseResponse setProductDetails(List<Product> productDetails, UserIdDetails userIdDetails, BaseResponse baseResponse, Organization org) {
        List<String> productIdList = org.getProductIdList();
        if (productIdList != null && !productIdList.isEmpty()) {
            for (String productId : productIdList) {
                Optional<Product> product = productRepo.findById(productId);
                if (product.isPresent()) {
                    productDetails.add(product.get());
                }
            }
            userIdDetails.setProductDetails(productDetails);
        }
        baseResponse.setPayload(userIdDetails);
        baseResponse.setMessage(String.valueOf(OrganizationMessageConstants.VALID_ORGANIZATION));
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    private BaseResponse verifyOrgBasedOnOrgRoleIdList(OrgLevelDetails orgDetails, List<String> orgRoleIdList, List<Product> productDetails, UserIdDetails userIdDetails, BaseResponse baseResponse) {
        Organization org = orgRepo.findByOrgUrl(orgDetails.getOrgUrl());
        List<OrganizationRole> orgRoleList = orgRoleRepo.findByOrgId(org.getId());
        for (OrganizationRole orgRole : orgRoleList) {
            if (orgRoleIdList.contains(orgRole.getId())) {
                return setProductDetails(productDetails, userIdDetails, baseResponse, org);
            }
        }
        LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG, ORGANIZATION_SERVICE_IMPL_CLASS, "verifyOrgBasedOnOrgRoleIdList", "Could not validate organization or fetch product details! ", "orgUrl ", orgDetails.getOrgUrl());
        throw new OrganizationServiceException(OrganizationMessageConstants.COULD_NOT_VALIDATE_ORG, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private void validateToken(String token) {
        boolean isTokenValid = tokenService.validateTokenRestTemplate(token);
        if (!isTokenValid) {
            throw new OrganizationServiceException(OrganizationMessageConstants.INVALID_TOKEN, HttpStatus.UNAUTHORIZED);
        }
    }

    private void setCurrentContextIfProjectIdPresent(HttpServletRequest request, CurrentContext currentContext) {
        if (!Objects.isNull(request.getHeader(HttpHeaderConstants.X_PROJECT_ID)) && !request.getHeader(HttpHeaderConstants.X_PROJECT_ID).isEmpty()) {
            String orgId = request.getHeader(HttpHeaderConstants.X_PROJECT_ID);
            Optional<Project> project = projectRepo.findById(orgId);
            if (project.isPresent()) {
                currentContext.setProjectId(project.get().getId());
                currentContext.setProjectName(project.get().getName());
            }
        }
    }

    private void setCurrentContextIfOrgIdPresent(HttpServletRequest request, CurrentContext currentContext) {
        if (!Objects.isNull(request.getHeader(HttpHeaderConstants.X_ORG_ID)) && !request.getHeader(HttpHeaderConstants.X_ORG_ID).isEmpty()) {
            String orgId = request.getHeader(HttpHeaderConstants.X_ORG_ID);
            Optional<Organization> org = orgRepo.findById(orgId);
            if (org.isPresent()) {
                currentContext.setOrgId(org.get().getId());
                currentContext.setOrgName(org.get().getName());
            }
        }
    }

    private BaseResponse verifyOrgIfTokenNull(OrgLevelDetails orgDetails, BaseResponse baseResponse) {
        if (orgDetails != null && orgDetails.getOrgUrl() != null) {
            Organization org = orgRepo.findByOrgUrl(orgDetails.getOrgUrl());
            if (org != null) {
                baseResponse.setMessage(String.valueOf(OrganizationMessageConstants.VALID_ORG));
                orgDetails.setOrgName(org.getName());
                orgDetails.setOrgUrl(org.getOrgUrl());
                orgDetails.setAdminEmail(org.getAdminEmail());
                orgDetails.setAdminName(org.getAdminName());
                orgDetails.setAlbaneroEmail(org.getAlbaneroEmail());
                baseResponse.setSuccess(true);
                return baseResponse;
            }
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG, ORGANIZATION_SERVICE_IMPL_CLASS, "verifyOrgIfTokenNull", "Invalid Organization", "orgUrl ", orgDetails.getOrgUrl());
            throw new OrganizationServiceException(OrganizationMessageConstants.INVALID_ORG, HttpStatus.BAD_REQUEST);
        }
        throw new OrganizationServiceException(OrganizationMessageConstants.INCOMPLETE_ORGANIZATION_DETAILS, HttpStatus.BAD_REQUEST);
    }

    @Override
    public BaseResponse addOrgMember(HttpServletRequest request, AddRemoveMemberRequest addMemberRequest)
            throws UnsupportedEncodingException, MessagingException {
        BaseResponse baseResponse = new BaseResponse();
        UserProfile user = new UserProfile();
        helperUtil.validateAddMemberRequest(addMemberRequest);
        Role role = roleRepo.findByRoleName(addMemberRequest.getRole());
        Optional<Organization> orgOpt = orgRepo.findById(addMemberRequest.getOrgId());
        helperUtil.checkRole(role);

        Organization org = helperUtil.validateOrganization(orgOpt);
        OrganizationRole orgRole = null;
        orgRole = orgRoleRepo.findByOrgIdAndRoleId(org.getId(), role.getId());
        if (orgRole == null) {
            orgRole = new OrganizationRole();
            orgRole.setOrgId(org.getId());
            orgRole.setRoleId(role.getId());
            orgRoleRepo.save(orgRole);
        }

        String token = requestUtil.extractJwtFromRequest(request);
        String member = requestUtil.usernameFromToken(token);

        //send invitation to the user to register into the platform
        //Hitting this link will ultimately going to call updateOrgMember to save the user details
        if (!helperUtil.checkForDuplicateEmail(addMemberRequest.getEmail())) {

            user.setEmailId(addMemberRequest.getEmail());

            emailUtil.sendOrgInviteEmail(request, member, addMemberRequest, org);

            baseResponse.setMessage("User invited for " + org.getName() + " Organization");
            baseResponse.setSuccess(true);
            return baseResponse;
        }

        user = userRepo.findByEmailId(addMemberRequest.getEmail().toLowerCase());
        UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(user.getId());
        List<String> orgRoleIdList = userOrgRole.getOrgRoleIdList() != null ? userOrgRole.getOrgRoleIdList() : new ArrayList<>();
        if (!orgRoleIdList.contains(orgRole.getId())) {
            orgRoleIdList.add(orgRole.getId());

            //provide default org watcher role in parent org

            String originName = request.getHeader(HttpHeaders.ORIGIN);
            Organization parentOrg = null;
            if (helperUtil.checkOriginName(originName)) {
                String orgUrl = originName.substring(8);
                parentOrg = orgRepo.findByOrgUrl(orgUrl);
            } else {
                parentOrg = orgRepo.findAllByOrderByIdAsc().get(0);
            }
            if (parentOrg != null) {
                OrganizationRole parentOrgRole = orgRoleRepo.findByOrgIdAndRoleId(parentOrg.getId(), roleRepo.findByRoleName(PermissionConstants.ORG_WATCHER).getId());
                if (parentOrgRole == null) {
                    parentOrgRole = new OrganizationRole();
                    parentOrgRole.setOrgId(parentOrg.getId());
                    parentOrgRole.setRoleId(roleRepo.findByRoleName(PermissionConstants.ORG_WATCHER).getId());
                    orgRoleRepo.save(parentOrgRole);
                }
                if (!helperUtil.isVaildParentOrgRole(orgRoleIdList, parentOrgRole, orgRole)) {
                    orgRoleIdList.add(parentOrgRole.getId());
                }
            }

            userOrgRole.setOrgRoleIdList(orgRoleIdList);
            userOrgRoleRepo.save(userOrgRole);

            baseResponse.setMessage(String.valueOf(OrganizationMessageConstants.USER_ADDED));
            baseResponse.setSuccess(true);
            return baseResponse;
        }
        throw new OrganizationServiceException(OrganizationMessageConstants.USER_ALREADY_MEMBER, HttpStatus.BAD_REQUEST);
    }

    @Override
    public BaseResponse updateOrgMember(HttpServletRequest request, RegistrationUser updatedUser) throws MessagingException, UnsupportedEncodingException {
        UserProfile user = null;
        BaseResponse baseResponse = new BaseResponse();
        RegisterUserResponse payload = new RegisterUserResponse();
        try {
            String token = updatedUser.getUserCode();
            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            encryptor.setPassword(encryptorPassword);
            String decryptedOtpToken = encryptor.decrypt(token);


            boolean isOtpValid = tokenService.validateTokenRestTemplate(decryptedOtpToken);
            if (!StringUtils.hasText(decryptedOtpToken) || !isOtpValid) {
                throw new OrganizationServiceException(OrganizationMessageConstants.INVALID_TOKEN, HttpStatus.UNAUTHORIZED);
            }

            user = helperUtil.validateUserDetails(updatedUser, decryptedOtpToken);
            user = userRepo.save(user);

            AddRemoveMemberRequest addMemberRequest = new ObjectMapper().convertValue(
                    requestUtil.getMappingsFromToken(decryptedOtpToken).getPayload(),
                    AddRemoveMemberRequest.class
            );

            Role memberRole = roleRepo.findByRoleName(addMemberRequest.getRole());
            Optional<Organization> orgOpt = orgRepo.findById(addMemberRequest.getOrgId());

            helperUtil.checkRole(memberRole);

            //setting org watcher in org role
            UserOrgRole userOrgRole = helperUtil.provideRoleInOrgAndProject(addMemberRequest, orgOpt, memberRole, request);
            userOrgRole.setUserId(user.getId());
            userOrgRoleRepo.save(userOrgRole);

            accStatusRepo.save(helperUtil.setUserAccountStatus(user));

            payload = helperUtil.saveMfaStatus(updatedUser, user, payload);

            Organization org = helperUtil.validateOrganization(orgOpt);

            emailUtil.sendApprovalEmail(request, user, org);

            FetchResponse requestDetails = rbaService.fetchRequestDetails(request);
            boolean isHistorySaved = authService.saveAuthHistory(user.getId(), requestDetails);
            if (isHistorySaved) {
                user.setRole(ROLE_ADMIN);
                userRepo.save(user);

                baseResponse.setMessage("Profile details updated.");
                baseResponse.setSuccess(true);
                baseResponse.setPayload(payload);
                return baseResponse;
            } else {
                throw new OrganizationServiceException(OrganizationMessageConstants.AUTH_HISTORY_NOT_SAVE, HttpStatus.INTERNAL_SERVER_ERROR);
            }
        } catch (OrganizationServiceException ex) {
            throw ex;
        } catch (Exception e) {
            //remove user details
            if (!Objects.isNull(user)) {
                helperUtil.removeUserDetails(user.getId());
            }
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, ORGANIZATION_SERVICE_IMPL_CLASS, "save", e.getMessage(), e.getStackTrace());
            throw new OrganizationServiceException(ACTION_FAILED_EXCEPTION.label, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public BaseResponse fetchListOfOrgs(HttpServletRequest request) {
        String method = "fetchListOfOrgs";
        BaseResponse baseResponse = new BaseResponse();
        List<OrgLevelDetails> orgDetailsList = new ArrayList<>();
        ObjectMapper mapper = new ObjectMapper();

        String token = requestUtil.extractJwtFromRequest(request);
        BaseResponse userIdDetailsResponse = requestUtil.getUserMappings(token);
        UserIdDetails userIdDetails = mapper.convertValue(userIdDetailsResponse.getPayload(), UserIdDetails.class);
        String username = userIdDetails.getUserProfileDetails().getUsername();
        UserProfile dbuser = authService.loadUserProfileByUsername(username);
        UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(dbuser.getId());
        List<Organization> orgList = new ArrayList<>();

        if (userOrgRole != null) {
            List<String> orgRoleIdList = userOrgRole.getOrgRoleIdList();
            if (orgRoleIdList != null) {

                for (String orgRoleId : orgRoleIdList) {
                    Optional<OrganizationRole> orgRole = getOrgRole(orgRoleId, dbuser);

                    Optional<Organization> org = getOrganisation(orgRole.get(), dbuser);

                    if (orgList.contains(org.get()))
                        continue;
                    orgList.add(org.get());

                    Optional<Role> role = roleRepo.findById(orgRole.get().getRoleId());
                    if (role.isEmpty()) {
                        LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, ORGANIZATION_SERVICE_IMPL_CLASS, method, "Role not found with this RoleId ", orgRole.get().getRoleId(), "UserId", dbuser.getId());
                        throw new OrganizationServiceException(OrganizationMessageConstants.valueOf("Role not found with this RoleId " + orgRole.get().getRoleId()), HttpStatus.NOT_FOUND);
                    } else {
                        //set organisation details
                        setOrganisationLevelDetails(org.get(), role.get(), orgDetailsList);
                    }
                }
                baseResponse.setPayload(orgDetailsList);
                baseResponse.setMessage(String.valueOf(OrganizationMessageConstants.ORGANIZATION_DETAILS_FETCHED));
                baseResponse.setSuccess(true);
                return baseResponse;
            }
        }
        throw new OrganizationServiceException(OrganizationMessageConstants.USER_ORGANIZATION_NOT_FOUND, HttpStatus.NOT_FOUND);
    }

    private void setOrganisationLevelDetails(Organization org, Role role, List<OrgLevelDetails> orgDetailsList) {
        OrgLevelDetails orgLevelDetails = new OrgLevelDetails();
        orgLevelDetails.setOrgName(org.getName());
        orgLevelDetails.setOrgId(org.getId());
        orgLevelDetails.setRole(role.getRoleName());
        List<String> productIdList = org.getProductIdList();
        List<Product> productDetails = new ArrayList<>();
        if (productIdList != null && !productIdList.isEmpty()) {
            for (String productId : productIdList) {
                Optional<Product> product = productRepo.findById(productId);
                if (product.isPresent()) {
                    productDetails.add(product.get());
                }
            }
            orgLevelDetails.setProductDetails(productDetails);
        }
        orgDetailsList.add(orgLevelDetails);
    }

    private Optional<Organization> getOrganisation(OrganizationRole orgRole, UserProfile dbuser) {
        Optional<Organization> org = orgRepo.findById(orgRole.getOrgId());
        if (org.isEmpty()) {
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, ORGANIZATION_SERVICE_IMPL_CLASS, "getOrganisation", "Org not found with this orgId ", orgRole.getOrgId(), "UserId", dbuser.getId());
            throw new OrganizationServiceException(OrganizationMessageConstants.valueOf("Org not found with this orgId " + orgRole.getOrgId()), HttpStatus.NOT_FOUND);
        }
        return org;
    }

    private Optional<OrganizationRole> getOrgRole(String orgRoleId, UserProfile dbuser) {
        Optional<OrganizationRole> orgRole = orgRoleRepo.findById(orgRoleId);
        if (orgRole.isEmpty()) {
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, ORGANIZATION_SERVICE_IMPL_CLASS, "validateOrgRole", "OrgRole not found with this orgRoleId ", orgRoleId, "UserId ", dbuser.getId());
            throw new OrganizationServiceException(OrganizationMessageConstants.valueOf("OrgRole not found with this orgRoleId " + orgRoleId), HttpStatus.NOT_FOUND);
        }
        return orgRole;
    }

    @Override
    public BaseResponse fetchListOfProducts() {
        BaseResponse baseResponse = new BaseResponse();

        List<Product> listOfProducts = productRepo.findAll();
        if (!listOfProducts.isEmpty()) {
            baseResponse.setPayload(listOfProducts);
            baseResponse.setMessage("Product details fetched!");
            baseResponse.setSuccess(true);
            return baseResponse;
        }
        throw new OrganizationServiceException(OrganizationMessageConstants.PRODUCT_LIST_NOT_FOUND, HttpStatus.NOT_FOUND);
    }

    @Override
    public BaseResponse fetchListOfProductsForOrganization(String orgId) {
        BaseResponse baseResponse = new BaseResponse();
        Optional<Organization> orgOpt = orgRepo.findById(orgId);
        if (orgOpt.isEmpty()) {
            throw new OrganizationServiceException(OrganizationMessageConstants.INVALID_ORG);
        }
        Organization org = orgOpt.get();
        List<String> productIdList = org.getProductIdList();
        List<Product> listOfProducts = new ArrayList<>();

        if (productIdList != null && !productIdList.isEmpty()) {
            for (String productId : productIdList) {
                Optional<Product> product = productRepo.findById(productId);
                if (product.isEmpty()) {
                    LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, ORGANIZATION_SERVICE_IMPL_CLASS, "fetchListOfProductsForOrganization", "Product not found with this productId ", productId, "orgId ", orgId);
                    throw new OrganizationServiceException(OrganizationMessageConstants.valueOf("Product not found with this productId " + productId), HttpStatus.NOT_FOUND);
                }
                listOfProducts.add(product.get());
            }
        }

        if (listOfProducts.isEmpty()) {
            baseResponse.setPayload(listOfProducts);
            baseResponse.setMessage("Product details fetched!");
            baseResponse.setSuccess(true);
            return baseResponse;
        }
        throw new OrganizationServiceException(OrganizationMessageConstants.PRODUCT_LIST_NOT_FOUND, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Override
    public BaseResponse fetchOrgDefaultRoles(Optional<String> orgId, Integer page, Integer pageSize) {
        BaseResponse baseResponse = new BaseResponse();

        List<Role> roles = new ArrayList<>(roleRepo.findByOrganizationDefaultRoleType());
        if (orgId.isPresent()) {
            roles.addAll(roleRepo.findByOrgIdAndOrganizationCustomRoleType(orgId));
        } else {
            roles.addAll(roleRepo.findByOrganizationCustomRoleType(orgId));
        }
        Pageable pageable = PageRequest.of(page, pageSize);
        PaginatedResponse rolesPaginated = helperUtil.listToPage(roles, pageable);

        baseResponse.setPayload(rolesPaginated);
        baseResponse.setMessage("Default Roles fetched along with corresponding permissions!");
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    @Override
    public BaseResponse fetchListOfUsersInOrg(HttpServletRequest request, OrgLevelDetails orgLevelDetails) throws JsonProcessingException {
        BaseResponse baseResponse = new BaseResponse();
        List<UserProfileDetails> userProfileDetailsList = new ArrayList<>();
        try {
            if (orgLevelDetails != null && orgLevelDetails.getOrgId() != null) {
                List<OrganizationRole> orgRoleList = orgRoleRepo.findByOrgId(orgLevelDetails.getOrgId());

                List<String> orgRoleIdList = orgRoleList.stream().map(OrganizationRole::getId).toList();

                List<UserOrgRole> userOrgRoleList = userOrgRoleRepo.findByOrgRoleIdListIn(orgRoleIdList);

                if (userOrgRoleList != null)
                    return fetchListOfUsersInOrg(orgLevelDetails, userOrgRoleList, orgRoleIdList, orgRoleList, userProfileDetailsList, baseResponse);
            }
            throw new OrganizationServiceException(OrganizationMessageConstants.INCOMPLETE_ORGANIZATION_DETAILS, HttpStatus.BAD_REQUEST);
        } catch (WebClientResponseException responseException) {
            baseResponse = new ObjectMapper().readValue(responseException.getResponseBodyAsString(), BaseResponse.class);
            throw new OrganizationServiceException(OrganizationMessageConstants.valueOf(baseResponse.getMessage()), responseException.getStatusCode());
        }
    }

    private BaseResponse fetchListOfUsersInOrg(OrgLevelDetails orgLevelDetails, List<UserOrgRole> userOrgRoleList, List<String> orgRoleIdList, List<OrganizationRole> orgRoleList, List<UserProfileDetails> userProfileDetailsList, BaseResponse baseResponse) {
        List<String> userIds = userOrgRoleList.stream().map(UserOrgRole::getUserId).toList();
        List<UserBlockStatusDto> userBlockStatusList = getUsersBlockStatus(userIds);
        for (UserOrgRole userOrgRole : userOrgRoleList) {
            Optional<UserProfile> user = userRepo.findById(userOrgRole.getUserId());
            if (user.isEmpty()) {
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, ORGANIZATION_SERVICE_IMPL_CLASS, "fetchListOfUsersInOrg", "User not found with this UserId ", userOrgRole.getUserId(), "orgId ", orgLevelDetails.getOrgId());
                throw new OrganizationServiceException(OrganizationMessageConstants.valueOf("User not found with this UserId " + userOrgRole.getUserId()), HttpStatus.NOT_FOUND);
            }
            AccountStatus userAccStatus = accStatusRepo.findByUserId(user.get().getId());
            if (userAccStatus != null && userAccStatus.getEmailStatus() != null && Boolean.TRUE.equals(userAccStatus.getEmailStatus().getIsVerified()))
                setUserProfileDetails(orgLevelDetails, userOrgRole, user.get(), orgRoleIdList, orgRoleList, userBlockStatusList, userProfileDetailsList);
        }
        baseResponse.setMessage("Successfully fetched users belonging to the organization");
        baseResponse.setPayload(userProfileDetailsList);
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    private void setUserProfileDetails(OrgLevelDetails orgLevelDetails, UserOrgRole userOrgRole, UserProfile user, List<String> orgRoleIdList, List<OrganizationRole> orgRoleList, List<UserBlockStatusDto> userBlockStatusList, List<UserProfileDetails> userProfileDetailsList) {
        UserProfileDetails userProfileDetails = userRoleService.setUserProfileDetailsWithoutImg(user);
        List<String> orgRoleIds = userOrgRole.getOrgRoleIdList().stream()
                .filter(orgRoleIdList::contains).toList();

        List<String> userRoles = orgRoleList.stream()
                .filter(p -> orgRoleIds.contains(p.getId()))
                .map(p -> {
                    Optional<Role> role = roleRepo.findById(p.getRoleId());
                    if (role.isEmpty()) {
                        LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, ORGANIZATION_SERVICE_IMPL_CLASS, SET_USER_PROFILE_DETAILS, "Role not found with this roleId ", p.getRoleId(), " orgId", orgLevelDetails.getOrgId());
                        throw new OrganizationServiceException(OrganizationMessageConstants.valueOf("Role not found with this roleId " + p.getRoleId()), HttpStatus.NOT_FOUND);
                    }
                    return role.get().getRoleName();
                })
                .toList();

        if (userOrgRole.getProjectOrgRoleIdList() != null && !userOrgRole.getProjectOrgRoleIdList().isEmpty()) {
            List<ProjectOrgRoleId> orgProjectRoleIds = userOrgRole.getProjectOrgRoleIdList();

            Set<String> projectOrgIds = getProjectOrgIds(orgLevelDetails, orgProjectRoleIds);

            List<ProjectOrg> projectsOrg = getProjectOrgs(orgLevelDetails, projectOrgIds);

            List<String> projectList = getProjectList(orgLevelDetails, projectsOrg);

            userProfileDetails.setProjectList(projectList);
        }
        Boolean status = HelperUtil.getBlockStatus(userBlockStatusList, userOrgRole.getUserId());
        userProfileDetails.setIsAccountBlock(status);
        userProfileDetails.setUserRoles(userRoles);
        userProfileDetails.setOrgId(orgLevelDetails.getOrgId());

        userProfileDetailsList.add(userProfileDetails);
    }

    private List<String> getProjectList(OrgLevelDetails orgLevelDetails, List<ProjectOrg> projectsOrg) {
        return projectsOrg.stream().filter(p -> p.getOrgId().equals(orgLevelDetails.getOrgId())).map(p -> {
            Optional<Project> project = projectRepo.findById(p.getProjectId());
            if (project.isEmpty()) {
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, ORGANIZATION_SERVICE_IMPL_CLASS, SET_USER_PROFILE_DETAILS, p, "projectId", p.getProjectId());
                throw new OrganizationServiceException(OrganizationMessageConstants.valueOf("Project not found with this ProjectOrgRoleId " + p), HttpStatus.NOT_FOUND);
            }
            return project.get().getName();
        }).toList();
    }

    private List<ProjectOrg> getProjectOrgs(OrgLevelDetails orgLevelDetails, Set<String> projectOrgIds) {
        return projectOrgIds.stream().map(p -> {
            Optional<ProjectOrg> projectOrg = projectOrgRepo.findById(p);
            if (projectOrg.isEmpty()) {
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, ORGANIZATION_SERVICE_IMPL_CLASS, SET_USER_PROFILE_DETAILS, "ProjectOrg not found with this ProjectOrgRoleId ", p, "orgId", orgLevelDetails.getOrgId());
                throw new OrganizationServiceException(OrganizationMessageConstants.valueOf("ProjectOrg not found with this ProjectOrgRoleId " + p), HttpStatus.INTERNAL_SERVER_ERROR);
            }
            return projectOrg.get();
        }).toList();
    }

    private Set<String> getProjectOrgIds(OrgLevelDetails orgLevelDetails, List<ProjectOrgRoleId> orgProjectRoleIds) {
        return orgProjectRoleIds.stream().map(p -> {
            Optional<ProjectOrgRole> projectOrgRole = projectOrgRoleRepo.findById(p.getProjectOrganizationRoleId());
            if (projectOrgRole.isEmpty()) {
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO, ORGANIZATION_SERVICE_IMPL_CLASS, SET_USER_PROFILE_DETAILS, "ProjectOrgRole not found with this ProjectOrgRoleId ", p, "orgId", orgLevelDetails.getOrgId());
                throw new OrganizationServiceException(OrganizationMessageConstants.valueOf("ProjectOrgRole not found with this ProjectOrgRoleId " + p), HttpStatus.NOT_FOUND);
            }
            return projectOrgRole.get().getProjectOrgId();
        }).collect(Collectors.toSet());
    }

    @Override
    public BaseResponse fetchListOfUnapprovedUsersInOrg(HttpServletRequest request, OrgLevelDetails orgLevelDetails) throws JsonProcessingException {
        BaseResponse baseResponse = new BaseResponse();
        List<UserProfileDetails> userProfileDetailsList = new ArrayList<>();
        String message;
        try {
            if (orgLevelDetails != null && orgLevelDetails.getOrgId() != null) {
                List<OrganizationRole> orgRoleList = orgRoleRepo.findByOrgId(orgLevelDetails.getOrgId());

                List<String> orgRoleIdList = orgRoleList.stream().map(p -> p.getId()).toList();

                List<UserOrgRole> userOrgRoleList = userOrgRoleRepo.findByOrgRoleIdListIn(orgRoleIdList);

                if (userOrgRoleList != null) {
                    List<String> userIds = userOrgRoleList.stream().map(UserOrgRole::getUserId).toList();
                    List<UserBlockStatusDto> userBlockStatusList = getUsersBlockStatus(userIds);
                    for (UserOrgRole userOrgRole : userOrgRoleList)
                        setUserProfileDetailsForUnapprovedUsers(orgLevelDetails, userOrgRole, userBlockStatusList, userProfileDetailsList);
                    if (!userProfileDetailsList.isEmpty()) {
                        message = "Successfully fetched unapproved users belonging to the organization";
                    } else {
                        message = "All the users are approved";
                    }
                    baseResponse.setMessage(message);
                    baseResponse.setPayload(userProfileDetailsList);
                    baseResponse.setSuccess(true);
                    return baseResponse;
                }
            }
            throw new OrganizationServiceException(OrganizationMessageConstants.INCOMPLETE_ORGANIZATION_DETAILS);
        } catch (WebClientResponseException responseException) {
            baseResponse = new ObjectMapper().readValue(responseException.getResponseBodyAsString(), BaseResponse.class);
            throw new OrganizationServiceException(OrganizationMessageConstants.valueOf(baseResponse.getMessage()), responseException.getStatusCode());
        }
    }

    /**
     * This method is set the user profile details for list of unapproved users in org
     *
     * @param orgLevelDetails
     * @param userOrgRole
     * @param userBlockStatusList
     * @param userProfileDetailsList
     */
    private void setUserProfileDetailsForUnapprovedUsers(OrgLevelDetails orgLevelDetails, UserOrgRole userOrgRole, List<UserBlockStatusDto> userBlockStatusList, List<UserProfileDetails> userProfileDetailsList) {
        Optional<UserProfile> user = userRepo.findById(userOrgRole.getUserId());
        if (user.isEmpty()) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, ORGANIZATION_SERVICE_IMPL_CLASS, SET_USER_PROFILE_DETAILS, " User not found with this userId ", userOrgRole.getUserId());
            throw new OrganizationServiceException(OrganizationMessageConstants.valueOf(" User not found with this userId " + userOrgRole.getUserId()), HttpStatus.NOT_FOUND);
        }
        AccountStatus userAccStatus = accStatusRepo.findByUserId(user.get().getId());
        if (userAccStatus != null && userAccStatus.getEmailStatus().getIsVerified() && Boolean.FALSE.equals(userAccStatus.getAccountApprovalStatus().getIsAccountApproved())) {
            UserProfileDetails userProfileDetails = userRoleService.setUserProfileDetails(user.get());
            userProfileDetails.setOrgId(orgLevelDetails.getOrgId());
            Boolean status = HelperUtil.getBlockStatus(userBlockStatusList, userOrgRole.getUserId());
            userProfileDetails.setIsAccountBlock(status);
            userProfileDetailsList.add(userProfileDetails);
        }
    }

    @Override
    public BaseResponse fetchListOfActiveUsersInOrg(HttpServletRequest request, OrgLevelDetails orgLevelDetails) throws JsonProcessingException {
        BaseResponse baseResponse = new BaseResponse();
        List<UserProfileDetails> userProfileDetailsList = new ArrayList<>();
        String message;
        try {
            if (orgLevelDetails != null && orgLevelDetails.getOrgId() != null) {
                List<OrganizationRole> orgRoleList = orgRoleRepo.findByOrgId(orgLevelDetails.getOrgId());

                List<String> orgRoleIdList = orgRoleList.stream().map(p -> p.getId()).toList();

                List<UserOrgRole> userOrgRoleList = userOrgRoleRepo.findByOrgRoleIdListIn(orgRoleIdList);

                if (userOrgRoleList != null) {
                    List<String> userIds = userOrgRoleList.stream().map(UserOrgRole::getUserId).toList();
                    List<UserBlockStatusDto> userBlockStatusList = getUsersBlockStatus(userIds);
                    for (UserOrgRole userOrgRole : userOrgRoleList)
                        setUserProfleDetails(orgLevelDetails, userOrgRole, userBlockStatusList, userProfileDetailsList);
                    if (!userProfileDetailsList.isEmpty()) {
                        message = "Successfully fetched active users belonging to the organization";
                    } else {
                        message = "All the users are either unapproved or approved and inactive";
                    }
                    baseResponse.setMessage(message);
                    baseResponse.setPayload(userProfileDetailsList);
                    baseResponse.setSuccess(true);
                    return baseResponse;
                }
            }
            throw new OrganizationServiceException(OrganizationMessageConstants.INCOMPLETE_ORGANIZATION_DETAILS);
        } catch (WebClientResponseException responseException) {
            baseResponse = new ObjectMapper().readValue(responseException.getResponseBodyAsString(), BaseResponse.class);
            throw new OrganizationServiceException(OrganizationMessageConstants.valueOf(baseResponse.getMessage()), responseException.getStatusCode());
        }
    }

    /**
     * This method is set the user profile details for list of active users in org
     *
     * @param orgLevelDetails
     * @param userOrgRole
     * @param userBlockStatusList
     * @param userProfileDetailsList
     */
    private void setUserProfleDetails(OrgLevelDetails orgLevelDetails, UserOrgRole userOrgRole, List<UserBlockStatusDto> userBlockStatusList, List<UserProfileDetails> userProfileDetailsList) {
        Optional<UserProfile> user = userRepo.findById(userOrgRole.getUserId());
        if (user.isEmpty()) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, ORGANIZATION_SERVICE_IMPL_CLASS, "setUserProfleDetails", " User not found with this userId", userOrgRole.getUserId());
            throw new OrganizationServiceException(OrganizationMessageConstants.valueOf(" User not found with this userId" + userOrgRole.getUserId()), HttpStatus.NOT_FOUND);
        }
        AccountStatus userAccStatus = accStatusRepo.findByUserId(user.get().getId());
        if (userAccStatus != null && userAccStatus.getEmailStatus().getIsVerified() && userAccStatus.getAccountActivationStatus() != null && Boolean.TRUE.equals(userAccStatus.getAccountActivationStatus().getIsActive())) {
            UserProfileDetails userProfileDetails = userRoleService.setUserProfileDetails(user.get());
            userProfileDetails.setStatusChangedAt(userAccStatus.getAccountActivationStatus().getStatusChangedAt());
            userProfileDetails.setStatusChangedBy(userAccStatus.getAccountActivationStatus().getStatusChangedBy());
            userProfileDetails.setOrgId(orgLevelDetails.getOrgId());
            Boolean status = HelperUtil.getBlockStatus(userBlockStatusList, userOrgRole.getUserId());
            userProfileDetails.setIsAccountBlock(status);
            userProfileDetailsList.add(userProfileDetails);
        }
    }

    @Override
    public BaseResponse fetchListOfInactiveUsersInOrg(HttpServletRequest request, OrgLevelDetails orgLevelDetails) throws JsonProcessingException {
        BaseResponse baseResponse = new BaseResponse();
        List<UserProfileDetails> userProfileDetailsList = new ArrayList<>();
        String message;
        try {
            if (orgLevelDetails != null && orgLevelDetails.getOrgId() != null) {
                List<OrganizationRole> orgRoleList = orgRoleRepo.findByOrgId(orgLevelDetails.getOrgId());

                List<String> orgRoleIdList = orgRoleList.stream().map(p -> p.getId()).toList();

                List<UserOrgRole> userOrgRoleList = userOrgRoleRepo.findByOrgRoleIdListIn(orgRoleIdList);

                if (userOrgRoleList != null) {
                    List<String> userIds = userOrgRoleList.stream().map(UserOrgRole::getUserId).toList();
                    List<UserBlockStatusDto> userBlockStatusList = getUsersBlockStatus(userIds);
                    for (UserOrgRole userOrgRole : userOrgRoleList) {
                        setUserProfileDetails(orgLevelDetails, userOrgRole, userBlockStatusList, userProfileDetailsList);
                    }
                    if (!userProfileDetailsList.isEmpty()) {
                        message = "Successfully fetched inactive users belonging to the organization";
                    } else {
                        message = "All the users are either unapproved or approved and active";
                    }
                    baseResponse.setMessage(message);
                    baseResponse.setPayload(userProfileDetailsList);
                    baseResponse.setSuccess(true);
                    return baseResponse;
                }
            }
            throw new OrganizationServiceException(OrganizationMessageConstants.INCOMPLETE_ORGANIZATION_DETAILS, HttpStatus.BAD_REQUEST);

        } catch (WebClientResponseException responseException) {
            baseResponse = new ObjectMapper().readValue(responseException.getResponseBodyAsString(), BaseResponse.class);
            throw new OrganizationServiceException(OrganizationMessageConstants.valueOf(baseResponse.getMessage()), responseException.getStatusCode());
        }
    }

    /**
     * This method is used to set the user profile details for list of inactive users in org
     *
     * @param orgLevelDetails
     * @param userOrgRole
     * @param userBlockStatusList
     * @param userProfileDetailsList
     */
    private void setUserProfileDetails(OrgLevelDetails orgLevelDetails, UserOrgRole userOrgRole, List<UserBlockStatusDto> userBlockStatusList, List<UserProfileDetails> userProfileDetailsList) {
        Optional<UserProfile> user = userRepo.findById(userOrgRole.getUserId());
        if (user.isEmpty()) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, ORGANIZATION_SERVICE_IMPL_CLASS, SET_USER_PROFILE_DETAILS, "User not found with this userId {}", userOrgRole.getUserId());
            throw new OrganizationServiceException(OrganizationMessageConstants.valueOf("User not found with this userId " + userOrgRole.getUserId()), HttpStatus.NOT_FOUND);
        }
        AccountStatus userAccStatus = accStatusRepo.findByUserId(user.get().getId());
        if (Boolean.TRUE.equals(userAccStatus != null && userAccStatus.getEmailStatus().getIsVerified() && userAccStatus.getAccountApprovalStatus().getIsAccountApproved() && userAccStatus.getAccountActivationStatus() != null) && Boolean.FALSE.equals(userAccStatus.getAccountActivationStatus().getIsActive())) {
            UserProfileDetails userProfileDetails = userRoleService.setUserProfileDetails(user.get());
            userProfileDetails.setStatusChangedAt(userAccStatus.getAccountActivationStatus().getStatusChangedAt());
            userProfileDetails.setStatusChangedBy(userAccStatus.getAccountActivationStatus().getStatusChangedBy());
            userProfileDetails.setOrgId(orgLevelDetails.getOrgId());
            Boolean status = HelperUtil.getBlockStatus(userBlockStatusList, userOrgRole.getUserId());
            userProfileDetails.setIsAccountBlock(status);
            userProfileDetailsList.add(userProfileDetails);
        }
    }

    /**
     * @param request         {@link HttpServletRequest}
     * @param orgLevelDetails {@link OrgLevelDetails}
     * @return {@link BaseResponse}
     */
    @Override
    public BaseResponse fetchListOfBlockedUsersInOrg(HttpServletRequest request, OrgLevelDetails orgLevelDetails) throws JsonProcessingException {
        BaseResponse baseResponse = new BaseResponse();
        List<UserProfileDetails> userProfileDetailsList = new ArrayList<>();
        String message;
        try {
            if (orgLevelDetails != null && orgLevelDetails.getOrgId() != null) {
                List<OrganizationRole> orgRoleList = orgRoleRepo.findByOrgId(orgLevelDetails.getOrgId());
                List<String> orgRoleIdList = orgRoleList.stream().map(p -> p.getId()).toList();
                List<UserOrgRole> userOrgRoleList = userOrgRoleRepo.findByOrgRoleIdListIn(orgRoleIdList);
                if (userOrgRoleList != null && !userOrgRoleList.isEmpty()) {
                    List<String> userIds = userOrgRoleList.stream().map(UserOrgRole::getUserId).toList();
                    List<UserBlockStatusDto> userBlockStatusList = getUsersBlockStatus(userIds);
                    if (userBlockStatusList != null && !userBlockStatusList.isEmpty()) {
                        setUserProfileDetailsList(orgLevelDetails, userBlockStatusList, userProfileDetailsList);
                    }
                    if (!userProfileDetailsList.isEmpty()) {
                        message = "Successfully fetched blocked users belonging to the organization";
                    } else {
                        message = "All the users are unblocked.";
                    }
                    baseResponse.setMessage(message);
                    baseResponse.setPayload(userProfileDetailsList);
                    baseResponse.setSuccess(true);
                    baseResponse.setStatusCode("200");
                    return baseResponse;
                }
            }
            throw new OrganizationServiceException(OrganizationMessageConstants.INCOMPLETE_ORGANIZATION_DETAILS);
        } catch (WebClientResponseException responseException) {
            baseResponse = new ObjectMapper().readValue(responseException.getResponseBodyAsString(), BaseResponse.class);
            throw new OrganizationServiceException(OrganizationMessageConstants.valueOf(baseResponse.getMessage()), responseException.getStatusCode());
        }
    }

    private void setUserProfileDetailsList(OrgLevelDetails orgLevelDetails, List<UserBlockStatusDto> userBlockStatusList, List<UserProfileDetails> userProfileDetailsList) {
        userBlockStatusList.forEach(userBlockStatus -> {
            Boolean status = userBlockStatus.getStatus();
            String userId = userBlockStatus.getUserid();
            if (Boolean.TRUE.equals(status)) {
                Optional<UserProfile> user = userRepo.findById(userId);
                if (user.isEmpty()) {
                    LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, ORGANIZATION_SERVICE_IMPL_CLASS, "setUserProfileDetailsList", "User not found with this userId", userId);
                    throw new OrganizationServiceException(OrganizationMessageConstants.valueOf("User not found with this userId " + userId), HttpStatus.NOT_FOUND);
                }
                UserProfileDetails userProfileDetails = userRoleService.setUserProfileDetails(user.get());
                userProfileDetails.setOrgId(orgLevelDetails.getOrgId());
                userProfileDetails.setIsAccountBlock(true);
                userProfileDetailsList.add(userProfileDetails);
            }
        });
    }

    /**
     * @param userIds {@link List<String>}
     * @return {@link Object}
     */
    public List<UserBlockStatusDto> getUsersBlockStatus(List<String> userIds) {
        List<UserBlockStatusDto> userBlockStatusList = new ArrayList<>();
        BaseResponse baseResponse = requestUtil.getUsersBlockStatus(userIds);
        if (Boolean.TRUE.equals(baseResponse.getSuccess())) {
            ObjectMapper mapper = new ObjectMapper();
            return List.of(mapper.convertValue(baseResponse.getPayload(), UserBlockStatusDto[].class));
        }
        return userBlockStatusList;
    }

    @Override
    public BaseResponse removeOrgMember(HttpServletRequest request, AddRemoveMemberRequest removeMemberRequest) {
        BaseResponse baseResponse = new BaseResponse();
        //validation of email and orgId
        validateEmailAndOrgId(removeMemberRequest);

        UserProfile user = userRepo.findByEmailId(removeMemberRequest.getEmail());
        UserOrgRole userOrgRole = userOrgRoleRepo.findByUserId(user.getId());
        List<OrganizationRole> orgRoleList = new ArrayList<>();

        if (removeMemberRequest.getRole() != null && !removeMemberRequest.getRole().isEmpty()) {
            Role role = roleRepo.findByRoleName(removeMemberRequest.getRole());
            OrganizationRole orgRole = orgRoleRepo.findByOrgIdAndRoleId(removeMemberRequest.getOrgId(),
                    role.getId());
            orgRoleList.add(orgRole);
        } else
            orgRoleList = orgRoleRepo.findByOrgId(removeMemberRequest.getOrgId());

        List<String> orgRoleIds = orgRoleList.stream().map(p -> p.getId()).toList();
        boolean atleastOneOrgRoleExists = false;

        if (userOrgRole.getOrgRoleIdList() != null) {
            userOrgRole.getOrgRoleIdList().removeIf(orgRoleIds::contains);
            for (String userOrgRoleId : userOrgRole.getOrgRoleIdList()) {
                OrganizationRole organizationRole = orgRoleRepo.findByIdAndOrgId(userOrgRoleId, removeMemberRequest.getOrgId());
                if (organizationRole != null) {
                    atleastOneOrgRoleExists = true;
                }
            }
        }

        //set user org role if project org roles are not empty and atleast one role exists
        setUserOrgRole(removeMemberRequest, userOrgRole, atleastOneOrgRoleExists);

        baseResponse.setMessage("User removed");
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    private void setUserOrgRole(AddRemoveMemberRequest removeMemberRequest, UserOrgRole userOrgRole, boolean atleastOneOrgRoleExists) {
        if (userOrgRole.getProjectOrgRoleIdList() != null && !atleastOneOrgRoleExists) {
            List<ProjectOrg> projectOrgList = projectOrgRepo.findByOrgId(removeMemberRequest.getOrgId());
            List<String> projectOrgRoleIds = new ArrayList<>();
            for (ProjectOrg projectOrg : projectOrgList) {
                List<ProjectOrgRole> projectOrgRoleList = projectOrgRoleRepo.findByProjectOrgId(projectOrg.getId());
                for (ProjectOrgRole projectOrgRole : projectOrgRoleList) {
                    projectOrgRoleIds.add(projectOrgRole.getId());
                }
            }
            userOrgRole.getProjectOrgRoleIdList().removeIf(p -> projectOrgRoleIds.contains(p.getProjectOrganizationRoleId()));
        }

        userOrgRoleRepo.save(userOrgRole);
    }

    private static void validateEmailAndOrgId(AddRemoveMemberRequest removeMemberRequest) {
        if (removeMemberRequest.getEmail() == null || removeMemberRequest.getEmail().trim().isEmpty()) {
            throw new OrganizationServiceException(OrganizationMessageConstants.INVALID_EMAIL);
        }

        if (removeMemberRequest.getOrgId() == null || removeMemberRequest.getOrgId().trim().isEmpty()) {
            throw new OrganizationServiceException(OrganizationMessageConstants.INVALID_ORG);
        }
    }

    @Override
    public BaseResponse fetchOrganizationDetails(String orgId) {
        BaseResponse baseResponse = new BaseResponse();
        Optional<Organization> organization = orgRepo.findById(orgId);
        if (organization.isPresent()) {
            baseResponse.setPayload(organization);
            baseResponse.setMessage(String.valueOf(OrganizationMessageConstants.ORGANIZATION_DETAILS_FETCHED));
            baseResponse.setSuccess(true);
            return baseResponse;
        }
        throw new OrganizationServiceException(OrganizationMessageConstants.ORGANIZATION_NOT_FOUND, HttpStatus.NOT_FOUND);
    }
}

