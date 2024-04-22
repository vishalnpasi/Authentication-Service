package com.albanero.authservice.common.util;

import com.albanero.authservice.common.constants.*;
import com.albanero.authservice.common.dto.ProjectOrgRoleId;
import com.albanero.authservice.common.dto.request.AddRemoveMemberRequest;
import com.albanero.authservice.common.dto.request.RegistrationUser;
import com.albanero.authservice.common.dto.response.*;
import com.albanero.authservice.exception.HelperUtilException;
import com.albanero.authservice.exception.OrganizationServiceException;
import com.albanero.authservice.exception.UserServiceException;
import com.albanero.authservice.model.*;
import com.albanero.authservice.model.Permissions;
import com.albanero.authservice.repository.*;
import com.albanero.authservice.service.AuthenticationService;
import com.albanero.authservice.service.impl.AuthServiceImpl;

import org.apache.commons.lang3.text.WordUtils;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.*;
import static com.albanero.authservice.common.constants.LoggerConstants.*;

@Service
public class HelperUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(HelperUtil.class);

    private static final String HELPER_UTIL = "HelperUtil";

    private final UserRepository userRepo;

    private final OrgRepository orgRepo;

    private final ProjectRepository projectRepo;

    private final ProjectOrgRepository projectOrgRepo;

    private final RequestUtil requestUtil;

    private final ModuleRepository moduleRepository;

    private final PasswordEncoder bcryptEncoder;

    private final RoleRepository roleRepo;

    private final OrgRoleRepository orgRoleRepo;

    private final ProjectOrgRoleRepository projectOrgRoleRepo;

    private final AccStatusRepository accStatusRepo;

    private final UserOrgRoleRepository userOrgRoleRepo;

    private final MfaStatusRepository mfaRepo;

    private final AuthenticationService authService;

    @Autowired
    public HelperUtil(UserRepository userRepo, OrgRepository orgRepo, ProjectRepository projectRepo,
                      ProjectOrgRepository projectOrgRepo, RequestUtil requestUtil, ModuleRepository moduleRepository,
                      PasswordEncoder bcryptEncoder, RoleRepository roleRepo, OrgRoleRepository orgRoleRepo,
                      ProjectOrgRoleRepository projectOrgRoleRepo, MfaStatusRepository mfaRepo,
                      AuthenticationService authService, AccStatusRepository accStatusRepo, UserOrgRoleRepository userOrgRoleRepo) {
        this.userRepo = userRepo;
        this.orgRepo = orgRepo;
        this.projectRepo = projectRepo;
        this.projectOrgRepo = projectOrgRepo;
        this.requestUtil = requestUtil;
        this.moduleRepository = moduleRepository;
        this.bcryptEncoder = bcryptEncoder;
        this.roleRepo = roleRepo;
        this.orgRoleRepo = orgRoleRepo;
        this.projectOrgRoleRepo = projectOrgRoleRepo;
        this.accStatusRepo = accStatusRepo;
        this.userOrgRoleRepo = userOrgRoleRepo;
        this.mfaRepo = mfaRepo;
        this.authService = authService;
    }

    /**
     * Method to validate user-name
     * Details - A username is considered valid if all the following constraints are
     * satisfied:
     * The username consists of 6 to 30 characters inclusive. If the username
     * consists of less than 6 or greater than 30 characters, then it is an invalid
     * username. The username can only contain alphanumeric characters and
     * underscores (_). Alphanumeric characters describe the character set
     * consisting of lowercase characters [a - z], uppercase characters [A - Z], and
     * digits [0 - 9]. The first character of the username must be an alphabetic
     * character, i.e., either lowercase character [a - z] or uppercase character [A
     * - Z].
     *
     * @param username {@link String}
     */
    public boolean isValidUsername(String username) {
        String regex = "^[A-Za-z0-9_.]{6,30}$";
        Pattern p = Pattern.compile(regex);

        if (username == null) {
            return false;
        }

        Matcher m = p.matcher(username);
        return m.matches();
    }

    /**
     * Method to validate user mail address
     *
     * @param email {@link String}
     */
    public boolean isValidEmail(String email) {
        String regex = "^([\\w.]+@[\\w.]+\\.[a-zA-Z]{2,})$";
        return email.matches(regex);
    }

    /**
     * Method to validate user password
     *
     * Details - A password is considered valid if all the following constraints are
     * satisfied:
     *
     * It contains at least 8 characters and at most 20 characters. It contains at
     * least one digit. It contains at least one upper case alphabet. It contains at
     * least one lower case alphabet. It contains at least one special character
     * which includes !@#$%&*()-+=^. It does not contain any white space.
     *
     * @param password {@link String}
     */
    public boolean isValidPassword(String password) {

        String regex = "^(?=.*[\\d])" + "(?=.*[a-z])(?=.*[A-Z])" + "(?=.*[!@#$%&()*-+=^.])" + "(?=\\S+$).{8,20}$";

        Pattern p = Pattern.compile(regex);

        if (password == null) {
            return false;
        }

        Matcher m = p.matcher(password);
        return m.matches();
    }

    /**
     * Method to check for duplicate username
     *
     * @param username  {@link String}
     */
    public boolean checkForDuplicateUsername(String username) {
        UserProfile existingUser = userRepo.findByUsername(username.toLowerCase());
        return (existingUser != null);
    }

    /**
     * Method to check for duplicate email
     *
     * @param email  {@link String}
     */
    public boolean checkForDuplicateEmail(String email) {
        UserProfile existingUser = userRepo.findByEmailId(email.toLowerCase());
        return (existingUser != null);
    }

    /**
     * Method to validate first name of the user
     *
     * @param firstName  {@link String}
     */
    public boolean isValidFirstName(String firstName) {
        return firstName.matches("[A-Za-z ]{1,20}");
    }

    /**
     * Method to validate last name of the user
     *
     * @param lastName  {@link String}
     */
    public boolean isValidLastName(String lastName) {
        return lastName.matches("[A-Za-z ]{1,20}");
    }


    /**
     * Method to generate QR link for MFA registration
     *
     * @param email  {@link String}
     *  @param secret  {@link String}
     */
    public static String generateQRUrl(String email, String secret , String albaneroInstance) {
        return MfaConstants.QR_PREFIX + URLEncoder.encode(String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s",
                albaneroInstance, email, secret, albaneroInstance), StandardCharsets.UTF_8);
    }


    /**
     * Method to load user entity details by username
     *
     * @param userName  {@link String}
     * @return UserDetails
     */
    public UserProfile loadDaoUserByUsername(String userName) throws UsernameNotFoundException {
        UserProfile user = userRepo.findByUsername(userName);
        if (user != null) {
            return user;
        }
        throw new HelperUtilException("User not found with the userName " + userName, HttpStatus.NOT_FOUND);
    }

    /**
     * Method to check whether the encrypted password and the plain password are
     * same
     *
     * @param plainPassword  {@link String}
     * @param hashedPassword  {@link String}
     * @return boolean
     */
    public boolean checkPass(String plainPassword, String hashedPassword) {
        try {
            return BCrypt.checkpw(plainPassword, hashedPassword);
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, HELPER_UTIL, "checkPass","Exception occurred while checking for valid password", e.getStackTrace());
            return false;
        }
    }


    public Boolean checkForDuplicateOrgName(String orgName) {
        Organization org = orgRepo.findByName(orgName);
        return org != null && org.getName().equalsIgnoreCase(orgName.trim());
    }

    public Boolean checkForOtherDuplicateOrgName(String orgName,String orgId) {
        Organization org = orgRepo.findByName(orgName);
        return org != null && org.getName().equalsIgnoreCase(orgName.trim()) && !org.getId().equals(orgId);
    }

    public Boolean checkForDuplicateOrgUrl(String orgUrl) {
        Organization org = orgRepo.findByOrgUrl(orgUrl);
        return org != null && org.getOrgUrl().equalsIgnoreCase(orgUrl.trim());
    }

    public boolean isValidOrganizationName(String organization) {
        return organization.matches("^[A-Za-z]+(\\s?[A-Za-z]){0,100}$");    //Set max limit of Organisatoin name as 100 to avoid stack overflow problem
    }

    public boolean isValidOrganizationUrl(String orgUrl) {
        return orgUrl.matches("^[a-z][a-z0-9]{0,100}([-.][a-z0-9]+){0,100}.albanero.io$");
    }

    public boolean checkForDuplicateProjectUrl(String projectName, String orgId) {
        List<ProjectOrg> projectOrgList = projectOrgRepo.findByOrgId(orgId);
        for (ProjectOrg projectOrg : projectOrgList) {
            Optional<Project> project = projectRepo.findById(projectOrg.getProjectId());
            if(project.isEmpty()){
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,"Project not found with this "+projectOrg.getProjectId()+" project ID.", HELPER_UTIL, "checkForDuplicateProjectUrl");
                throw new HelperUtilException("Project not found with this "+projectOrg.getProjectId()+" project ID.", HttpStatus.NOT_FOUND);
            }
            if (project.get().getName().equalsIgnoreCase(projectName.trim())) {
                return true;
            }
        }
        return false;
    }

    public boolean stringEmpty(String inputString) {
        return inputString == null || "".equals(inputString);
    }

    public boolean isValidRole(String roleString) {
        return roleString.equals(PermissionConstants.ORG_WATCHER) || roleString.equals(PermissionConstants.ORG_ADMIN) || roleString.equals(PermissionConstants.PROJECT_ADMIN) || roleString.equals(PermissionConstants.DATA_ENGINEER) || roleString.equals(PermissionConstants.DATA_OPERATIONS) || roleString.equals(PermissionConstants.ROOT_USER) || roleString.equals(PermissionConstants.DATA_GOVERNANCE_LEAD) || roleString.equals(PermissionConstants.DATA_STEWARD) || roleString.equals(PermissionConstants.BUSINESS_STEWARD) || roleString.equals(PermissionConstants.M3_OPERATIONS_LEAD);
    }

    public  boolean isValidRoleType (String roleType) {
        return roleType.equals(PermissionConstants.PROJECT_DEFAULT) || roleType.equals(PermissionConstants.ORGANIZATION_DEFAULT);
    }

    public static boolean isValidRegex (String regex) {
        PatternSyntaxException exc = null;
        try {
            Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            exc = e;
        }
        return exc == null;
    }

    public static boolean isValidApiMethod(String apiMethod) {
        return Arrays.asList(PermissionConstants.validApiMethods()).contains(apiMethod);
    }

    public PaginatedResponse listToPage(List<?> classList, Pageable pageable) {
        PaginatedResponse paginatedResponse = new PaginatedResponse();
        int start = (int)pageable.getOffset();
        int end = Math.min((start + pageable.getPageSize()), classList.size());
        Page<?> paged = new PageImpl<>(classList.subList(start, end), pageable, classList.size());
        paginatedResponse.setData(paged.getContent());
        paginatedResponse.setTotalCount(classList.size());
        return paginatedResponse;
    }

    public static String getUserAccountStatus (AccountStatus accountStatus ) {
        if (accountStatus.getEmailStatus().getIsVerified() != null && !accountStatus.getEmailStatus().getIsVerified()) {
            return AuthConstants.ACCOUNT_UNVERIFIED;
        }
        if (accountStatus.getAccountApprovalStatus().getIsAccountApproved() != null && !accountStatus.getAccountApprovalStatus().getIsAccountApproved()) {
            return AuthConstants.ACCOUNT_UNAPPROVED;
        }
        if (accountStatus.getAccountActivationStatus() != null && !accountStatus.getAccountActivationStatus().getIsActive()) {
            return AuthConstants.ACCOUNT_DEACTIVATED;
        }
        return AuthConstants.ACCOUNT_ACTIVE;
    }

    /**
     * To get string Value of HttpStatus code
     *
     * @param httpStatus {@link HttpStatus}
     * @return {@link String}
     */
    public static String stringValueHttpStatus(HttpStatus httpStatus) {
        return String.valueOf(httpStatus.value());
    }

    /**
     * To get the User block status from userBlockStatusList
     *
     * @param userBlockStatusList {@link List}
     * @param userId           {@link String}
     * @return {@link Boolean}
     */
    public static Boolean getBlockStatus(List<UserBlockStatusDto> userBlockStatusList, String userId) {
        try {
            Optional<UserBlockStatusDto> userBlockStatus = userBlockStatusList.stream()
                    .filter(userStatus -> userStatus.getUserid().equals(userId))
                    .findFirst();
            if (userBlockStatus.isPresent()) {
                return userBlockStatus.get().getStatus();
            }
        } catch (Exception e) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, HELPER_UTIL, "getBlockStatus", e.getMessage(), e.getStackTrace());
            return false;
        }
        return false;
    }

    public String getSpaceSeparatedName(String hyphenSeperatedString) {
        return WordUtils.capitalizeFully(hyphenSeperatedString.replace("-", " "));
    }

    public static String getHyphenatedName(String moduleName) {
        return moduleName.replace(" ", "-").toLowerCase();
    }

    public ModuleNameDto setModuleNameDtoFromModule(Modules module, Boolean isSelected){
        ModuleNameDto moduleNameDto = new ModuleNameDto();
        moduleNameDto.setLabel(module.getModuleName());
        moduleNameDto.setId(module.getId());
        moduleNameDto.setUniqueLabel(getHyphenatedName(module.getModuleName()));
        moduleNameDto.setIsSelected(isSelected);
        moduleNameDto.setIndeterminate(false);
        return moduleNameDto;
    }

    public ModuleNameDto setModuleNameDtoFromPermissions(Permissions permission, Boolean isSelected){
        ModuleNameDto moduleNamePermission = new ModuleNameDto();
        moduleNamePermission.setId(permission.getId());
        moduleNamePermission.setIndeterminate(false);
        moduleNamePermission.setUniqueLabel(getHyphenatedName(permission.getPermissionTitle()));
        moduleNamePermission.setLabel(permission.getPermissionTitle());
        moduleNamePermission.setIsSelected(isSelected);
        return moduleNamePermission;
    }

    public ModuleNameDto setModuleNameDtoFromSubmodules(SubModules subModule, Boolean isSelected){
        ModuleNameDto moduleNameSubModule = new ModuleNameDto();
        moduleNameSubModule.setId(subModule.getId());
        moduleNameSubModule.setIndeterminate(false);
        moduleNameSubModule.setLabel(subModule.getSubModuleName());
        moduleNameSubModule.setUniqueLabel(getHyphenatedName(subModule.getSubModuleName()));
        moduleNameSubModule.setIsSelected(isSelected);
        return moduleNameSubModule;
    }

    public UserProfile getUserProfileFromRequest(HttpServletRequest request) {
        String jwt = requestUtil.extractJwtFromRequest(request);
        String userName = requestUtil.usernameFromToken(jwt);
        return authService.loadUserProfileByUsername(userName);
    }

    public Boolean checkIfAdminOrHasPermissionModuleOrSubModule(Set<String> arrayList, String searchId, Boolean isAdmin){
        boolean isSelected = false;
        if(arrayList.contains(searchId)){
            isSelected = true;
        } else {
            isSelected = isAdmin;
        }
        return isSelected;
    }

    public Boolean checkIfAdminOrHasListPermission(List<String> arrayList, String searchId, Boolean isAdmin){
        Boolean isSelected = false;
        if(arrayList.contains(searchId)){
            isSelected = true;
        } else {
            isSelected = isAdmin;
        }
        return isSelected;
    }

    public boolean checkForDuplicateModuleName(String moduleName, String oldModuleName) {
        Modules modules = moduleRepository.findByModuleName(moduleName);
        if (modules != null) {
            if(!oldModuleName.isEmpty()){
                return !modules.getModuleName().equals(oldModuleName);
            }
            return true;
        }
        return false;
    }

    public String getPermissionName(Modules modules, SubModules subModules, String permissionTitle) {
        String hyphenatedModuleName = getHyphenatedName(modules.getModuleName());
        String hyphenatedPermissionName = getHyphenatedName(permissionTitle);
        String hyphenatedSubModuleName = null;
        if(!Objects.isNull(subModules.getSubModuleName())) {
            hyphenatedSubModuleName = getHyphenatedName(subModules.getSubModuleName());
            return hyphenatedModuleName + "." + hyphenatedSubModuleName + "." + hyphenatedPermissionName;
        } else {
            return hyphenatedModuleName + "." + hyphenatedPermissionName;
        }
    }

    public String getScreenName(Modules modules, SubModules subModules) {
        String hyphenatedModuleName = getHyphenatedName(modules.getModuleName());
        String hyphenatedSubModuleName = null;
        if(!Objects.isNull(subModules.getSubModuleName())) {
            hyphenatedSubModuleName = getHyphenatedName(subModules.getSubModuleName());
            return hyphenatedModuleName + "." + hyphenatedSubModuleName;
        } else {
            return hyphenatedModuleName;
        }
    }

    /**
     * Method to validate BaseResponse and return ResponseEntity
     *
     * @param baseResponse {@link BaseResponse}
     * @param status {@link HttpStatus}
     * @return {@link ResponseEntity <BaseResponse>}
     */
    public static ResponseEntity<BaseResponse> getResponseEntity(BaseResponse baseResponse, HttpStatus status) {
        if (baseResponse != null && baseResponse.getStatusCode() != null) {
            HttpStatus httpStatus = HttpStatus.resolve(Integer.parseInt(baseResponse.getStatusCode()));
            baseResponse.setStatusCode(null);
            if (httpStatus != null) return new ResponseEntity<>(baseResponse, httpStatus);
        }
        if (baseResponse != null) baseResponse.setStatusCode(null);
        return new ResponseEntity<>(baseResponse, status);
    }

    public UserProfile setUserProfile(RegistrationUser user) {
        UserProfile newUser = new UserProfile();
        newUser.setFirstName(user.getFirstName().substring(0, 1).toUpperCase() + user.getFirstName().substring(1).trim());
        newUser.setLastName(user.getLastName().substring(0, 1).toUpperCase() + user.getLastName().substring(1).trim());
        newUser.setUsername(user.getUsername().trim());
        newUser.setEmailId(user.getMailId().toLowerCase().trim());
        newUser.setPassword(bcryptEncoder.encode(user.getPassword()));
        newUser.setRole(AuthServiceImpl.ROLE_ADMIN);
        return newUser;
    }

    public MfaStatus setMfaStatus ( String userId, RegistrationUser user ) {
        MfaStatus mfaStatus = new MfaStatus();
        mfaStatus.setUserId(userId);
        if (Boolean.TRUE.equals(user.getIsUsing2FA()) && user.getSecret() != null) {
            Mfa mfa = new Mfa();
            mfa.setMfaSecret(user.getSecret());
            mfa.setProviderApp(MfaConstants.PROVIDERAPP);
            mfaStatus.setMfa(mfa);
            mfaStatus.setUserId(userId);
            mfaStatus.setIsEnabled(true);
        } else {
            mfaStatus.setIsEnabled(false);
        }
        return mfaStatus;
    }

    public SecurityQuestionStatus setSecurityQuestions ( String userId, RegistrationUser user ){
        SecurityQuestionStatus securityQuestionStatus = new SecurityQuestionStatus();
        securityQuestionStatus.setQuestion(user.getSecurityQuestion());
        securityQuestionStatus.setAnswer(user.getSecurityAnswer());
        securityQuestionStatus.setUserId(userId);
        return securityQuestionStatus;
    }

    public String getVerificationToken (String userEmail) {
        return requestUtil.verificationToken(userEmail, TokenConstants.USER_VERIFICATION_TOKEN_DURATION);
    }

    public AccountStatus setAccountStatusNewUser(UserProfile newUser){
        AccountStatus accountStatus = new AccountStatus();
        EmailStatus emailStatus = new EmailStatus();
        emailStatus.setIsVerified(false);
        emailStatus.setVerificationCode(getVerificationToken(newUser.getEmailId()));
        accountStatus.setEmailStatus(emailStatus);
        AccountApprovalStatus accountApprovalStatus = new AccountApprovalStatus();
        accountApprovalStatus.setIsAccountApproved(false);
        accountStatus.setAccountApprovalStatus(accountApprovalStatus);
        accountStatus.setUserId(newUser.getId());
        return accountStatus;
    }

    public AccountStatus updateAccountStatus ( AccountStatus accountStatus, String verificationToken ){
        EmailStatus emailStatus = accountStatus.getEmailStatus();
        emailStatus.setVerificationCode(verificationToken);
        emailStatus.setIsVerified(false);
        accountStatus.setEmailStatus(emailStatus);
        AccountApprovalStatus accountApprovalStatus = new AccountApprovalStatus();
        accountApprovalStatus.setIsAccountApproved(false);
        accountStatus.setAccountApprovalStatus(accountApprovalStatus);
        return accountStatus;
    }

    public MfaStatus updateMfaDetails ( MfaStatus mfaStatus, String secret ) {
        mfaStatus.getMfa().setMfaSecret(secret);
        mfaStatus.setIsEnabled(true);
        mfaStatus.getMfa().setProviderApp(MfaConstants.PROVIDERAPP);
        return mfaStatus;
    }
    /**
     * Method to Validate OrgId And ProjectId
     * validate Organization_Id and Project_Id And return UserServiceException if it's invalid
     *
     * @param httpServletRequest {@link HttpServletRequest}
     * @throws UserServiceException If the OrgId and ProjectId is null or Invalid.
     */
    public void checkOrgIdAndProjectId(HttpServletRequest httpServletRequest){
        String orgId = httpServletRequest.getHeader(HttpHeaderConstants.X_ORG_ID);
        String projectId = httpServletRequest.getHeader(HttpHeaderConstants.X_PROJECT_ID);
        String isOrgLevel = httpServletRequest.getHeader(HttpHeaderConstants.X_ORG_LEVEL);

        if (orgId == null || orgId.isBlank()) {
            throw new UserServiceException(ORG_ID_IS_NOT_PRESENT_EXCEPTION, HttpStatus.BAD_REQUEST);
        }
        Optional<Organization> orgOpt = orgRepo.findById(orgId);
        if (orgOpt.isEmpty()) {
            throw new UserServiceException(INVALID_ORG_ID_EXCEPTION, HttpStatus.NOT_FOUND);
        }
        if(isOrgLevel == null || !isOrgLevel.equals("true")) {

            if (projectId == null || projectId.isBlank()) {
                throw new UserServiceException(PROJECT_ID_IS_NOT_PRESENT_EXCEPTION, HttpStatus.BAD_REQUEST);
            }
            Optional<Project> project = projectRepo.findById(projectId);
            if (project.isEmpty()) {
                throw new UserServiceException(INVALID_PROJECT_ID_EXCEPTION, HttpStatus.NOT_FOUND);
            }
        }
    }
    public void validateAddMemberRequest(AddRemoveMemberRequest addMemberRequest){
        String method = "validateAddMemberRequest";
        if (addMemberRequest.getEmail() == null || !isValidEmail(addMemberRequest.getEmail())) {
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,OrganizationMessageConstants.INVALID_EMAIL,HELPER_UTIL,method);
            throw new OrganizationServiceException(OrganizationMessageConstants.INVALID_EMAIL,HttpStatus.BAD_REQUEST);
        }
        if (addMemberRequest.getRole() == null || addMemberRequest.getRole().isBlank()) {
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,OrganizationMessageConstants.ROLE_EMPTY,HELPER_UTIL,method);
            throw new OrganizationServiceException(OrganizationMessageConstants.ROLE_EMPTY,HttpStatus.BAD_REQUEST);
        }
        if (addMemberRequest.getOrgId() == null || addMemberRequest.getOrgId().isBlank()) {
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,OrganizationMessageConstants.ORG_EMPTY,HELPER_UTIL,method);
            throw new OrganizationServiceException(OrganizationMessageConstants.ORG_EMPTY,HttpStatus.BAD_REQUEST);
        }
    }
    public void checkRole(Role role){
        if (role == null) {
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,OrganizationMessageConstants.MEMBER_ROLE_DONT_EXIST,HELPER_UTIL,"checkRole");
            throw new OrganizationServiceException(OrganizationMessageConstants.MEMBER_ROLE_DONT_EXIST,HttpStatus.NOT_FOUND);
        }
    }
    public Organization validateOrganization(Optional<Organization> orgOpt){
        if (orgOpt.isEmpty()) {
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,OrganizationMessageConstants.MEMBER_ORG_DONT_EXIST,HELPER_UTIL,"validateOrganization");
            throw new OrganizationServiceException(OrganizationMessageConstants.MEMBER_ORG_DONT_EXIST,HttpStatus.NOT_FOUND);
        }
        return orgOpt.get();
    }
    public boolean checkOriginName(String originName){
        return (originName != null && !originName.isEmpty());
    }
    public boolean  isVaildParentOrgRole(List<String> orgRoleIdList,OrganizationRole parentOrgRole,OrganizationRole orgRole){
        return orgRoleIdList.contains(parentOrgRole.getId()) || orgRole.getId().equals(parentOrgRole.getId());
    }
    public boolean checkRoleType(RoleType roleType , String projectId , String orgId){
        return (roleType.getRoleTypeName().equals(PermissionConstants.PROJECT_DEFAULT) || roleType.getProjectId().contains(projectId) || roleType.getOrgId().contains(orgId));
    }
    public UserProfile validateUserDetails(RegistrationUser updatedUser,String decryptedOtpToken){
        String method = "validateUserDetails";
        UserProfile user = new UserProfile();

        String usermail = requestUtil.getEmailFromToken(decryptedOtpToken);
        if (usermail == null || usermail.isBlank() || usermail.isEmpty()) {
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,OrganizationMessageConstants.USERMAIL_EMPTY,HELPER_UTIL,method);
            throw new OrganizationServiceException(OrganizationMessageConstants.USERMAIL_EMPTY,HttpStatus.NOT_FOUND);
        }
        if(checkForDuplicateEmail(usermail)){
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,OrganizationMessageConstants.USER_ALREADY_REGISTER,HELPER_UTIL,method);
            throw new OrganizationServiceException(OrganizationMessageConstants.USER_ALREADY_REGISTER,HttpStatus.BAD_REQUEST);
        }

        user.setEmailId(usermail);

        if (updatedUser.getUsername() == null || !isValidUsername(updatedUser.getUsername()) || checkForDuplicateUsername(updatedUser.getUsername())) {
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,OrganizationMessageConstants.INVALID_USERNAME,HELPER_UTIL,method);
            throw new OrganizationServiceException(OrganizationMessageConstants.INVALID_USERNAME,HttpStatus.BAD_REQUEST);
        }
        user.setUsername(updatedUser.getUsername());

        if (!isValidPassword(updatedUser.getPassword().trim())) {
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,OrganizationMessageConstants.INVALID_PASSWORD,HELPER_UTIL,method);
            throw new OrganizationServiceException(OrganizationMessageConstants.INVALID_PASSWORD,HttpStatus.BAD_REQUEST);
        }
        if (!updatedUser.getPassword().equals(updatedUser.getConfirmedPassword())) {
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,OrganizationMessageConstants.PASSWORD_MISMATCH,HELPER_UTIL,method);
            throw new OrganizationServiceException(OrganizationMessageConstants.PASSWORD_MISMATCH,HttpStatus.BAD_REQUEST);
        }
        user.setPassword(bcryptEncoder.encode(updatedUser.getPassword()));

        if (updatedUser.getFirstName() == null || updatedUser.getFirstName().isBlank() || !isValidFirstName(updatedUser.getFirstName().trim())){
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,OrganizationMessageConstants.INVALID_FIRSTNAME,HELPER_UTIL,method);
            throw new OrganizationServiceException(OrganizationMessageConstants.INVALID_FIRSTNAME,HttpStatus.BAD_REQUEST);
        }
        user.setFirstName(updatedUser.getFirstName());

        if (updatedUser.getLastName() == null || updatedUser.getLastName().isBlank() || !isValidFirstName(updatedUser.getLastName().trim())){
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,OrganizationMessageConstants.INVALID_LASTNAME,HELPER_UTIL,method);
            throw new OrganizationServiceException(OrganizationMessageConstants.INVALID_LASTNAME,HttpStatus.BAD_REQUEST);
        }
        user.setLastName(updatedUser.getLastName());
        return user;
    }
    public RegisterUserResponse saveMfaStatus(RegistrationUser updatedUser, UserProfile user , RegisterUserResponse payload){

        MfaStatus mfaStatus = new MfaStatus();
        if (Boolean.TRUE.equals(updatedUser.getIsUsing2FA()) && updatedUser.getSecret() != null) {
            payload.setIsMfaEnabled(true);
            mfaStatus.setUserId(user.getId());
            Mfa mfa = new Mfa();
            mfa.setMfaSecret(updatedUser.getSecret());
            mfa.setProviderApp(MfaConstants.PROVIDERAPP);
            mfaStatus.setMfa(mfa);
            mfaStatus.setUserId(user.getId());
            mfaStatus.setIsEnabled(true);
            mfaRepo.save(mfaStatus);
        } else {
            mfaStatus.setIsEnabled(false);
            mfaStatus.setUserId(user.getId());
            mfaRepo.save(mfaStatus);
        }
        return payload;
    }
    public AccountStatus setUserAccountStatus(UserProfile user){
        AccountStatus accountStatus = new AccountStatus();
        EmailStatus emailStatus = new EmailStatus();
        emailStatus.setIsVerified(true);
        accountStatus.setEmailStatus(emailStatus);
        AccountApprovalStatus accountApprovalStatus = new AccountApprovalStatus();
        accountApprovalStatus.setIsAccountApproved(false);
        accountStatus.setAccountApprovalStatus(accountApprovalStatus);
        accountStatus.setUserId(user.getId());

        return accountStatus;
    }
    public UserOrgRole provideRoleInOrgAndProject(AddRemoveMemberRequest addMemberRequest,Optional<Organization> orgOpt, Role memberRole, HttpServletRequest request){

        String method = "provideRoleInOrgAndProject";
        List<String> orgRoleIdList = new ArrayList<>();
        UserOrgRole userOrgRole = new UserOrgRole();

        if (addMemberRequest.getProjectId() != null && !addMemberRequest.getProjectId().isBlank()) {

            // provide Role in Particular Project using orgId , role and ProjectId from otpToken

            Organization organization = validateOrganization(orgOpt);
            Role roleInOrg = roleRepo.findByRoleName(PermissionConstants.ORG_WATCHER);
            OrganizationRole organizationRole = orgRoleRepo.findByOrgIdAndRoleId(addMemberRequest.getOrgId(), roleInOrg.getId());
            Optional<Project> projectOpt = projectRepo.findById(addMemberRequest.getProjectId());
            if (projectOpt.isEmpty()) {
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,PROJECT_ID_INVALID_EXCEPTION,HELPER_UTIL,method);
                throw new UserServiceException(PROJECT_ID_INVALID_EXCEPTION, HttpStatus.BAD_REQUEST);
            }
            Project project = projectOpt.get();
            ProjectOrg projectOrg = projectOrgRepo.findByProjectIdAndOrgId(project.getId(), organization.getId());
            ProjectOrgRole projectOrgRole = projectOrgRoleRepo.findByProjectOrgIdAndRoleId(projectOrg.getId(), memberRole.getId());
            RoleType roleType = memberRole.getRoleType();
            if (projectOrgRole == null) {
                if (roleType.getRoleTypeName().equals(PermissionConstants.PROJECT_DEFAULT) || roleType.getProjectId().contains(project.getId()) || roleType.getOrgId().contains(organization.getId())) {
                    projectOrgRole = new ProjectOrgRole();
                    projectOrgRole.setProjectOrgId(projectOrg.getId());
                    projectOrgRole.setRoleId(memberRole.getId());
                    projectOrgRoleRepo.save(projectOrgRole);
                } else {
                    LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,ROLE_IS_NOT_ASSOCIATED_TO_PROJECT_EXCEPTION,HELPER_UTIL,method);
                    throw new UserServiceException(ROLE_IS_NOT_ASSOCIATED_TO_PROJECT_EXCEPTION, HttpStatus.FORBIDDEN);
                }
            }

            List<ProjectOrgRoleId> projectOrgRoleIdList = new ArrayList<>();
            projectOrgRoleIdList.add(new ProjectOrgRoleId(projectOrgRole.getId(),false));

            orgRoleIdList.add(organizationRole.getId());

            userOrgRole.setProjectOrgRoleIdList(projectOrgRoleIdList);
        } else {
            // provide Role in Particular Organization using orgId and role from otpToken

            Organization org = validateOrganization(orgOpt);
            OrganizationRole orgRole = orgRoleRepo.findByOrgIdAndRoleId(org.getId(), memberRole.getId());
            if (orgRole == null) {
                orgRole = new OrganizationRole();
                orgRole.setOrgId(org.getId());
                orgRole.setRoleId(memberRole.getId());
                orgRoleRepo.save(orgRole);
            }
            orgRoleIdList.add(orgRole.getId());
        }
        //provide default org watcher role in parent org

        orgRoleIdList = provideDefaultOrgWatcherRole(orgRoleIdList,request);
        userOrgRole.setOrgRoleIdList(orgRoleIdList);

        return userOrgRole;
    }
    public List<String> provideDefaultOrgWatcherRole(List<String> orgRoleIdList,HttpServletRequest request){

        Organization parentOrg = null;
        Role roleOrgWatcher = roleRepo.findByRoleName(PermissionConstants.ORG_WATCHER);
        String originName = request.getHeader(HttpHeaders.ORIGIN);
        if((originName != null && !originName.isEmpty())) {
            String orgUrl = originName.substring(8);
            parentOrg = orgRepo.findByOrgUrl(orgUrl);
        } else {
            parentOrg = orgRepo.findAllByOrderByIdAsc().get(0);
        }
        if(parentOrg != null) {
            OrganizationRole parentOrgRole = orgRoleRepo.findByOrgIdAndRoleId(parentOrg.getId(),roleOrgWatcher.getId());
            if(parentOrgRole == null)
            {
                parentOrgRole =  new OrganizationRole();
                parentOrgRole.setOrgId(parentOrg.getId());
                parentOrgRole.setRoleId(roleOrgWatcher.getId());
                orgRoleRepo.save(parentOrgRole);
            }
            if(!orgRoleIdList.contains(parentOrgRole.getId())) {
                orgRoleIdList.add(parentOrgRole.getId());
            }
        }
        return orgRoleIdList;
    }

     /** Method to get Albanero Instance Name
     *
     * method for give albanero instance name from which instance user login
     *
     * @params httpServletRequest {@link HttpServletRequest}
     * @return {@link String}
     */
    public String getAlbaneroInstance(HttpServletRequest request) {

        String albaneroInstance = MfaConstants.ALBANERO_PLATFORM;

        String originName = request.getHeader(HttpHeaders.ORIGIN);
        if (originName != null && !originName.isEmpty()) {
            String orgUrl = originName.substring(8);
            String instanceName = orgUrl.split("\\.")[0];
            instanceName = instanceName.substring(0, 1).toUpperCase() + instanceName.substring(1);

            albaneroInstance = "Albanero " + instanceName + " Platform";
        }
        return albaneroInstance;
    }

    /**
     * Method to validate user details and save updated user details
     *
     * @params user {@link UserProfile}
     * @params updateUser {@link RegistrationUser}
     * @return {@link RegisterUserResponse}
     */
    public RegisterUserResponse validateUserDetails(UserProfile user, RegistrationUser updatedUser) {
        RegisterUserResponse payload = new RegisterUserResponse();

        if (updatedUser.getFirstName() != null) {
            if (!isValidFirstName(updatedUser.getFirstName())) {
                payload.setFirstNameMessage("Given first name is invalid!");
            } else if (updatedUser.getFirstName().equals(user.getFirstName())) {
                payload.setFirstNameMessage("Given first name is already exists!");
            } else {
                user.setFirstName(updatedUser.getFirstName());
                payload.setFirstNameMessage("Given first name is updated!");
            }
        }
        if (updatedUser.getLastName() != null) {
            if (!isValidFirstName(updatedUser.getLastName())) {
                payload.setLastNameMessage("Given last name is invalid!");
            } else if (updatedUser.getLastName().equals(user.getLastName())) {
                payload.setLastNameMessage("Given last name is already exists!");
            } else {
                user.setLastName(updatedUser.getLastName());
                payload.setLastNameMessage("Given last name is updated!");
            }
        }
        userRepo.save(user);
        return payload;
    }


    public void removeUserDetails(String userId){
        userRepo.deleteById(userId);

        if (!Objects.isNull(mfaRepo.findByUserId(userId))){
            mfaRepo.deleteByUserId(userId);
        }

        if(!Objects.isNull(accStatusRepo.findByUserId(userId))){
            accStatusRepo.deleteByUserId(userId);
        }

        if(!Objects.isNull(userOrgRoleRepo.findByUserId(userId))){
            userOrgRoleRepo.deleteByUserId(userId);
        }

        deleteAuthHistory(userId);
    }

    public Boolean deleteAuthHistory(String userId) {
        try {
            if (userId != null) {
                ResponseEntity<BaseResponse> deleteHistoryResponse = requestUtil.deleteAuthHistory(userId);
                BaseResponse response = deleteHistoryResponse.getBody();
                if (response != null) {
                    return response.getSuccess();
                }
            }
            return false;
        } catch (Exception e) {
            LOGGER.warn(AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG, "saveAuthHistory", e.getMessage(),e.getStackTrace());
            return false;
        }
    }
}
