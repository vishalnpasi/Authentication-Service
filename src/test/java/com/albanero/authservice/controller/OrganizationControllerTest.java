//package com.albanero.authservice.controller;
//
//import com.albanero.authservice.common.dto.request.OrgLevelDetails;
//import com.albanero.authservice.common.dto.response.BaseResponse;
//import com.albanero.authservice.common.util.RequestUtil;
//import com.albanero.authservice.model.*;
//import com.albanero.authservice.repository.AccStatusRepository;
//import com.albanero.authservice.repository.OrgRoleRepository;
//import com.albanero.authservice.repository.UserOrgRoleRepository;
//import com.albanero.authservice.repository.UserRepository;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.boot.test.mock.mockito.MockBean;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//
//import jakarta.servlet.http.HttpServletRequest;
//import java.util.ArrayList;
//import java.util.HashMap;
//import java.util.List;
//import java.util.Optional;
//
//import static org.junit.jupiter.api.Assertions.assertEquals;
//
//@SpringBootTest
//class OrganizationControllerTest {
//
//    private static final Logger LOGGER = LoggerFactory.getLogger(OrganizationControllerTest.class);
//
//    @Autowired
//    private OrganizationController organizationController;
//
//    @Mock
//    private HttpServletRequest request;
//
//    @MockBean
//    private OrgRoleRepository orgRoleRepository;
//
//    @MockBean
//    private UserOrgRoleRepository userOrgRoleRepo;
//
//    @MockBean
//    private RequestUtil requestUtil;
//
//    @MockBean
//    private UserRepository userRepository;
//
//    @MockBean
//    private AccStatusRepository accStatusRepository;
//
//    @BeforeEach
//    public void mockingService() {
//        LOGGER.info("Stared Mocking.....");
//
//        LOGGER.info("Mocking OrganizationRoleRepository");
//        List<OrganizationRole> organizationRoleList = new ArrayList<OrganizationRole>();
//        OrganizationRole organizationRole = new OrganizationRole();
//        organizationRole.setId("7896");
//        organizationRole.setOrgId("1236");
//        organizationRole.setRoleId("1147");
//        organizationRoleList.add(organizationRole);
//        Mockito.when(orgRoleRepository.findByOrgId("1236")).thenReturn((organizationRoleList));
//
//        LOGGER.info("Mocking UserOrgRoleRepository");
//        List<String> orgRoleIdList = new ArrayList<>();
//        orgRoleIdList.add("7896");
//        List<UserOrgRole> userOrgRoleList = new ArrayList<>();
//        UserOrgRole userOrgRole = new UserOrgRole();
//        userOrgRole.setId("7896");
//        userOrgRole.setUserId("125");
//        userOrgRoleList.add(userOrgRole);
//        Mockito.when(userOrgRoleRepo.findByOrgRoleIdListIn(orgRoleIdList)).thenReturn(userOrgRoleList);
//
//        LOGGER.info("Mocking UserOrgRoleRepository");
//        List<String> userIds = new ArrayList<>();
//        userIds.add("125");
//        ArrayList<Object> usersBlockStatus = new ArrayList<>();
//        HashMap<String, Object> userBlockStatus = new HashMap<>();
//        userBlockStatus.put("userid", "125");
//        userBlockStatus.put("status", true);
//        usersBlockStatus.add(userBlockStatus);
//        BaseResponse baseResponse = new BaseResponse();
//        baseResponse.setSuccess(true);
//        baseResponse.setPayload(usersBlockStatus);
//        Mockito.when(requestUtil.getUsersBlockStatus(userIds)).thenReturn(baseResponse);
//
//        LOGGER.info("Mocking UserRepository");
//        UserProfile user = new UserProfile();
//        user.setId("125");
//        Mockito.when(userRepository.findById("125")).thenReturn(Optional.of(user));
//
//        LOGGER.info("Mocking accStatusRepository");
//        AccountStatus accountStatus = new AccountStatus();
//        AccountApprovalStatus accountApprovalStatus = new AccountApprovalStatus();
//        accountApprovalStatus.setIsAccountApproved(true);
//        accountStatus.setAccountApprovalStatus(accountApprovalStatus);
//        AccountActivationStatus accountActivationStatus = new AccountActivationStatus();
//        accountActivationStatus.setIsActive(true);
//        accountStatus.setAccountActivationStatus(accountActivationStatus);
//        Mockito.when(accStatusRepository.findByUserId("125")).thenReturn(accountStatus);
//
//        LOGGER.info("Mocking is Done.......");
//    }
//
//
//    @Test
//    void getUsersInOrg_BlockStatus_Test_1() {
//        try {
//            LOGGER.info("Inside OrganizationControllerTest::getUsersInOrg_BlockStatus_Test method");
//            OrgLevelDetails orgLevelDetails = new OrgLevelDetails();
//            orgLevelDetails.setOrgId("1236");
//            Optional<String> userStatus = Optional.of("block");
//            ResponseEntity<BaseResponse> response = organizationController.getUsersInOrg(request, orgLevelDetails, userStatus);
//            assertEquals(HttpStatus.OK, response.getStatusCode());
//            assertEquals("Successfully fetched block users belonging to the organization", response.getBody().getMessage());
//            assertEquals(true, response.getBody().getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside OrganizationControllerTest::getUsersInOrg_BlockStatus_Test method : Unknown error {} ", e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void getUsersInOrg_BlockStatus_Test_2() {
//        try {
//            LOGGER.info("Inside OrganizationControllerTest::getUsersInOrg_BlockStatus_Test method");
//            OrgLevelDetails orgLevelDetails = new OrgLevelDetails();
//            Optional<String> userStatus = Optional.of("block");
//            ResponseEntity<BaseResponse> response = organizationController.getUsersInOrg(request, orgLevelDetails, userStatus);
//            assertEquals(HttpStatus.OK, response.getStatusCode());
//            assertEquals("Could not fetch block users", response.getBody().getMessage());
//            assertEquals(false, response.getBody().getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside OrganizationControllerTest::getUsersInOrg_BlockStatus_Test method : Unknown error {} ", e.getMessage(), e);
//        }
//    }
//
//}