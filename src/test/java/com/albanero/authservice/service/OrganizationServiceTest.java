//package com.albanero.authservice.service;
//
//import com.albanero.authservice.common.dto.request.OrgLevelDetails;
//import com.albanero.authservice.common.dto.request.UserProfileDetails;
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
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.boot.test.mock.mockito.MockBean;
//
//import jakarta.servlet.http.HttpServletRequest;
//import java.util.ArrayList;
//import java.util.HashMap;
//import java.util.List;
//
//import static org.junit.jupiter.api.Assertions.assertEquals;
//import static org.mockito.Mockito.when;
//
//@SpringBootTest
//class OrganizationServiceTest {
//
//    private static final Logger LOGGER = LoggerFactory.getLogger(OrganizationServiceTest.class);
//
//    @Autowired
//    private OrganizationService organizationService;
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
//        when(orgRoleRepository.findByOrgId("1236")).thenReturn((organizationRoleList));
//
//        LOGGER.info("Mocking UserOrgRoleRepository");
//        List<String> orgRoleIdList = new ArrayList<>();
//        orgRoleIdList.add("7896");
//        List<UserOrgRole> userOrgRoleList = new ArrayList<>();
//        UserOrgRole userOrgRole = new UserOrgRole();
//        userOrgRole.setId("7896");
//        userOrgRole.setUserId("125");
//        userOrgRoleList.add(userOrgRole);
//        when(userOrgRoleRepo.findByOrgRoleIdListIn(orgRoleIdList)).thenReturn(userOrgRoleList);
//
//        LOGGER.info("Mocking RequestUtil");
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
//        when(requestUtil.getUsersBlockStatus(userIds)).thenReturn(baseResponse);
//
//        LOGGER.info("Mocking UserRepository");
//        UserProfile user = new UserProfile();
//        user.setId("125");
//        when(userRepository.findById("125")).thenReturn(java.util.Optional.of(user));
//
//        LOGGER.info("Mocking AccStatusRepository");
//        AccountStatus accountStatus = new AccountStatus();
//        AccountApprovalStatus accountApprovalStatus = new AccountApprovalStatus();
//        accountApprovalStatus.setIsAccountApproved(true);
//        accountStatus.setAccountApprovalStatus(accountApprovalStatus);
//        AccountActivationStatus accountActivationStatus = new AccountActivationStatus();
//        accountActivationStatus.setIsActive(true);
//        accountStatus.setAccountActivationStatus(accountActivationStatus);
//        when(accStatusRepository.findByUserId("125")).thenReturn(accountStatus);
//
//        LOGGER.info("Mocking is Done.......");
//    }
//
//
//    @Test
//    void fetchListOfBlockUsersInOrgTest_1() {
//        try {
//            LOGGER.info("Inside OrganizationServiceTest::fetchListOfBlockUsersInOrgTest_1 method");
//            OrgLevelDetails orgLevelDetails = new OrgLevelDetails();
//            orgLevelDetails.setOrgId("1236");
//            BaseResponse response = organizationService.fetchListOfBlockedUsersInOrg(request, orgLevelDetails);
//            assertEquals(true, response.getSuccess());
//            assertEquals("Successfully fetched blocked users belonging to the organization", response.getMessage());
//            assertEquals("200", response.getStatusCode());
//        } catch (Exception e) {
//            LOGGER.error("Inside OrganizationServiceTest::fetchListOfBlockUsersInOrgTest_1 method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    /**
//     * When OrgId is not given
//     */
//    @Test
//    void fetchListOfBlockUsersInOrgTest_2() {
//        try {
//            LOGGER.info("Inside OrganizationServiceTest::fetchListOfBlockUsersInOrgTest_2 method");
//            OrgLevelDetails orgLevelDetails = new OrgLevelDetails();
//            BaseResponse response = organizationService.fetchListOfBlockedUsersInOrg(request, orgLevelDetails);
//            assertEquals(false, response.getSuccess());
//            String message = "Could not fetch block users";
//            assertEquals(message, response.getMessage());
//        } catch (Exception e) {
//            LOGGER.error("Inside OrganizationServiceTest::fetchListOfBlockUsersInOrgTest_2 method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    /**
//     * When All the users are unblocked
//     */
//    @Test
//    void fetchListOfBlockUsersInOrgTest_3() {
//        try {
//            LOGGER.info("Mocking UserOrgRoleRepository");
//            List<String> userIds = new ArrayList<>();
//            userIds.add("125");
//            ArrayList<Object> usersBlockStatus = new ArrayList<>();
//            HashMap<String, Object> userBlockStatus = new HashMap<>();
//            userBlockStatus.put("userid", "125");
//            userBlockStatus.put("status", false);
//            usersBlockStatus.add(userBlockStatus);
//            BaseResponse baseResponse = new BaseResponse();
//            baseResponse.setSuccess(true);
//            baseResponse.setPayload(usersBlockStatus);
//            when(requestUtil.getUsersBlockStatus(userIds)).thenReturn(baseResponse);
//            LOGGER.info("Inside OrganizationServiceTest::fetchListOfBlockUsersInOrgTest_3 method");
//            OrgLevelDetails orgLevelDetails = new OrgLevelDetails();
//            orgLevelDetails.setOrgId("1236");
//            BaseResponse response = organizationService.fetchListOfBlockedUsersInOrg(request, orgLevelDetails);
//            assertEquals(true, response.getSuccess());
//            assertEquals("All the users are unblocked.", response.getMessage());
//        } catch (Exception e) {
//            LOGGER.error("Inside OrganizationServiceTest::fetchListOfBlockUsersInOrgTest_3 method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    /**
//     * To set List of UserProfileDetails
//     *
//     * @return {@link List<UserProfileDetails>}
//     */
//    public List<UserProfileDetails> setUserProfileDetailsList() {
//        List<UserProfileDetails> userProfileDetailsList = new ArrayList<>();
//        UserProfileDetails userProfileDetails = new UserProfileDetails();
//        userProfileDetails.setOrgId("62bd7c7facd31950f86d82d9");
//        userProfileDetailsList.add(userProfileDetails);
//        return userProfileDetailsList;
//    }
//
//
//    /**
//     * To set BaseResponse
//     *
//     * @param success {@link Boolean}
//     * @param message {@link String}
//     * @param payload {@link Object}
//     * @return {@link BaseResponse}
//     */
//    public BaseResponse setBaseResponse(Boolean success, String message, Object... payload) {
//        BaseResponse baseResponse = new BaseResponse();
//        baseResponse.setSuccess(success);
//        baseResponse.setMessage(message);
//        if (payload.length > 0) baseResponse.setPayload(payload);
//        return baseResponse;
//    }
//}
