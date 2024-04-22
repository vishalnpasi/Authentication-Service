//package com.albanero.authservice.service;
//
//import com.albanero.authservice.common.dto.request.ChangePasswordRequest;
//import com.albanero.authservice.common.dto.request.ProjectLevelDetails;
//import com.albanero.authservice.common.dto.request.UserAccountStatus;
//import com.albanero.authservice.common.dto.response.BaseResponse;
//import com.albanero.authservice.common.util.EmailUtil;
//import com.albanero.authservice.common.util.RequestUtil;
//import com.albanero.authservice.model.*;
//import com.albanero.authservice.repository.AccStatusRepository;
//import com.albanero.authservice.repository.UserRepository;
//import com.albanero.authservice.repository.UserSecRepository;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.boot.test.mock.mockito.MockBean;
//
//import jakarta.servlet.http.HttpServletRequest;
//import java.util.ArrayList;
//import java.util.Date;
//import java.util.Optional;
//
//import static org.junit.jupiter.api.Assertions.assertEquals;
//
//@SpringBootTest
//class UserRoleServiceTest {
//
//    private static final Logger LOGGER = LoggerFactory.getLogger(UserRoleServiceTest.class);
//
//    @Autowired
//    private UserRoleService userRoleService;
//
//    @Mock
//    private HttpServletRequest request;
//
//    @MockBean
//    private RequestUtil requestUtil;
//
//    @Test
//    void setDefaultProjectRole_Test() {
//        try {
//            LOGGER.info("Inside UserRoleServiceTest::setDefaultProjectRole_Test method");
//            ProjectLevelDetails projectLevelDetails = new ProjectLevelDetails();
//            projectLevelDetails.setProjectId("63033dc14e1f697734d64ccd");
//            projectLevelDetails.setRoleId("62e00562f8ad8c22e5cc1594");
//            BaseResponse response = userRoleService.setUserDefaultProjectRole(request, projectLevelDetails);
//            assertEquals(true, response.getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside UserServiceTest::setDefaultProjectRole_Test method : Unknown error {} ", e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void fetchDefaultProjectRole_Test() {
//        try {
//            LOGGER.info("Inside UserRoleServiceTest::fetchDefaultProjectRole_Test method");
//            BaseResponse response = userRoleService.fetchUserDefaultProjectRole(request, "63033dc14e1f697734d64ccd");
//            assertEquals(true, response.getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside UserServiceTest::fetchDefaultProjectRole_Test method : Unknown error {} ", e.getMessage(), e);
//        }
//    }
//}