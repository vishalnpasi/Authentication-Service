//package com.albanero.authservice.service;
//
//import com.albanero.authservice.common.constants.PermissionConstants;
//import com.albanero.authservice.common.dto.request.AddMembersRequest;
//import com.albanero.authservice.common.dto.request.MembersDetailsRequest;
//import com.albanero.authservice.common.dto.response.AddMemberResponse;
//import com.albanero.authservice.common.dto.response.BaseResponse;
//import com.albanero.authservice.common.util.EmailUtil;
//import com.albanero.authservice.common.util.HelperUtil;
//import com.albanero.authservice.common.util.RequestUtil;
//import com.albanero.authservice.model.*;
//import com.albanero.authservice.repository.*;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.boot.test.mock.mockito.MockBean;
//import org.springframework.http.HttpStatus;
//
//import jakarta.servlet.http.HttpServletRequest;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.Optional;
//
//import static org.junit.jupiter.api.Assertions.assertEquals;
//import static org.powermock.api.mockito.PowerMockito.when;
//
//@SpringBootTest
//class ProjectServiceTest {
//    private static final Logger LOGGER = LoggerFactory.getLogger(ProjectServiceTest.class);
//
//    @Autowired
//    private ProjectService projectService;
//
//    @MockBean
//    private HttpServletRequest request;
//
//    @MockBean
//    private RoleRepository roleRepository;
//
//    @MockBean
//    private OrgRepository orgRepository;
//
//    @MockBean
//    private OrgRoleRepository orgRoleRepository;
//
//    @MockBean
//    private ProjectRepository projectRepository;
//
//    @MockBean
//    private ProjectOrgRepository projectOrgRepository;
//
//    @MockBean
//    private ProjectOrgRoleRepository projectOrgRoleRepository;
//
//    @MockBean
//    private RequestUtil requestUtil;
//
//    @MockBean
//    private EmailUtil emailUtil;
//
//    @MockBean
//    private UserRepository userRepository;
//
//    @MockBean
//    private UserOrgRoleRepository userOrgRoleRepository;
//
//    @BeforeEach
//    public void mockingService() {
//        Role role = new Role();
//        role.setRole("ROLE_ADMIN");
//        role.setId("5124");
//        RoleType roleType = new RoleType();
//        roleType.setProjectId(Optional.of("4251"));
//        role.setRoleType(roleType);
//        when(roleRepository.findByRoleName("ROLE_ADMIN")).thenReturn(role);
//        Role roleAsWatcher = role;
//        roleAsWatcher.setId("5125");
//        when(roleRepository.findByRoleName(PermissionConstants.ORG_WATCHER)).thenReturn(roleAsWatcher);
//
//        Organization organization = new Organization();
//        organization.setId("2541");
//        when(orgRepository.findById("2541")).thenReturn(Optional.of(organization));
//
//        OrganizationRole orgRole = new OrganizationRole();
//        orgRole.setId("1524");
//        when(orgRoleRepository.findByOrgIdAndRoleId("2541", roleAsWatcher.getId())).thenReturn(orgRole);
//
//        Project project = new Project();
//        project.setId("4251");
//        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
//
//        ProjectOrg projectOrg = new ProjectOrg();
//        project.setId("4252");
//        when(projectOrgRepository.findByProjectIdAndOrgId(project.getId(), organization.getId())).thenReturn(projectOrg);
//
//        ProjectOrgRole projectOrgRole = new ProjectOrgRole();
//        when(projectOrgRoleRepository.findByProjectOrgIdAndRoleId(projectOrg.getId(), role.getId())).thenReturn(projectOrgRole);
//
//        when(requestUtil.extractJwtFromRequest(request)).thenReturn("token");
//        when(requestUtil.usernameFromToken("token")).thenReturn("username");
//
//        UserOrgRole userOrgRole = new UserOrgRole();
//        userOrgRole.setId("7896");
//        userOrgRole.setUserId("522");
//        when(userOrgRoleRepository.findByUserId("522")).thenReturn(userOrgRole);
//    }
//
//    /**
//     * For new user
//     */
//    @Test
//    void addProjectMember_for_new() {
//        try {
//            LOGGER.info("Inside ProjectServiceTest::addProjectMember_for_new method");
//            AddMembersRequest memberRequest = new AddMembersRequest();
//            memberRequest.setProjectId("4251");
//            memberRequest.setOrgId("2541");
//            MembersDetailsRequest membersDetails = new MembersDetailsRequest();
//            List<String> emailIds = new ArrayList<>();
//            emailIds.add("test@albanero.io");
//            membersDetails.setEmailIds(emailIds);
//            membersDetails.setRole("ROLE_ADMIN");
//            List<MembersDetailsRequest> membersDetailsList = new ArrayList<>();
//            membersDetailsList.add(membersDetails);
//            memberRequest.setMembersDetails(membersDetailsList);
//
//            BaseResponse response = projectService.addProjectMember(request, memberRequest);
//
//            assertEquals(true, response.getSuccess());
//            assertEquals("Users are added Successfully!", response.getMessage());
//            assertEquals(HelperUtil.stringValueHttpStatus(HttpStatus.OK), response.getStatusCode());
//            List<AddMemberResponse> payload = (List<AddMemberResponse>) response.getPayload();
//            AddMemberResponse memberDetails = payload.get(0);
//            assertEquals(emailIds.get(0), memberDetails.getEmail());
//            assertEquals("User invited!", memberDetails.getMessage());
//            assertEquals(true, memberDetails.getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside ProjectServiceTest::addProjectMember_for_new method : Unknown error {} ", e.getMessage(), e);
//        }
//    }
//
//    /**
//     * For Existing user
//     */
//    @Test
//    void addProjectMember_for_old() {
//        try {
//            LOGGER.info("Inside ProjectServiceTest::addProjectMember_for_new method");
//            UserProfile userProfile = new UserProfile();
//            userProfile.setId("522");
//            userProfile.setEmailId("test@albanero.io");
//            when(userRepository.findByEmailId("test@albanero.io")).thenReturn(userProfile);
//
//            AddMembersRequest memberRequest = new AddMembersRequest();
//            memberRequest.setProjectId("4251");
//            memberRequest.setOrgId("2541");
//            MembersDetailsRequest membersDetails = new MembersDetailsRequest();
//            List<String> emailIds = new ArrayList<>();
//            emailIds.add("test@albanero.io");
//            membersDetails.setEmailIds(emailIds);
//            membersDetails.setRole("ROLE_ADMIN");
//            List<MembersDetailsRequest> membersDetailsList = new ArrayList<>();
//            membersDetailsList.add(membersDetails);
//            memberRequest.setMembersDetails(membersDetailsList);
//
//
//            BaseResponse response = projectService.addProjectMember(request, memberRequest);
//
//            assertEquals(true, response.getSuccess());
//            assertEquals("Users are added Successfully!", response.getMessage());
//            assertEquals(HelperUtil.stringValueHttpStatus(HttpStatus.OK), response.getStatusCode());
//            List<AddMemberResponse> payload = (List<AddMemberResponse>) response.getPayload();
//            AddMemberResponse memberDetails = payload.get(0);
//            assertEquals(emailIds.get(0), memberDetails.getEmail());
//            assertEquals("User added!", memberDetails.getMessage());
//            assertEquals(true, memberDetails.getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside ProjectServiceTest::addProjectMember_for_new method : Unknown error {} ", e.getMessage(), e);
//        }
//    }
//}