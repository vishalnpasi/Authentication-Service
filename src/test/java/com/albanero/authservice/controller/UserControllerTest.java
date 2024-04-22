//package com.albanero.authservice.controller;
//
//import com.albanero.authservice.common.dto.request.ChangePasswordRequest;
//import com.albanero.authservice.common.dto.request.UserAccountStatus;
//import com.albanero.authservice.common.dto.response.AccountStatusUpdate;
//import com.albanero.authservice.common.dto.response.BaseResponse;
//import com.albanero.authservice.common.util.EmailUtil;
//import com.albanero.authservice.common.util.HelperUtil;
//import com.albanero.authservice.common.util.RequestUtil;
//import com.albanero.authservice.model.*;
//import com.albanero.authservice.repository.AccStatusRepository;
//import com.albanero.authservice.repository.UserRepository;
//import com.albanero.authservice.repository.UserSecRepository;
//import com.albanero.authservice.service.UserService;
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
//import java.util.*;
//
//import static org.junit.jupiter.api.Assertions.*;
//
//@SpringBootTest
//class UserControllerTest {
//
//    private static final Logger LOGGER = LoggerFactory.getLogger(UserControllerTest.class);
//
//    @Autowired
//    private UserController userController;
//
//    @Mock
//    private HttpServletRequest request;
//
//    @MockBean
//    private RequestUtil requestUtil;
//
//
//    @MockBean
//    private UserRepository userRepository;
//
//    @MockBean
//    private AccStatusRepository accStatusRepository;
//
//    @MockBean
//    private EmailUtil emailUtil;
//
//    @MockBean
//    private UserSecRepository userSecRepository;
//
//    @BeforeEach
//    void mockingService() {
//        LOGGER.info("Mocking RequestUtil");
//        Mockito.when(requestUtil.extractJwtFromRequest(request)).thenReturn("123");
//        Mockito.when(requestUtil.usernameFromToken("123")).thenReturn("username");
//        BaseResponse unblockUser =  new BaseResponse();
//        unblockUser.setStatusCode("200");
//        Mockito.when(requestUtil.unblockUser("125")).thenReturn(unblockUser);
//        Mockito.when(requestUtil.validateTokenFromTokenService("eyJhbGciOiJIUzUxMiJ9.eyJ1c2VyTWFwcGluZ3MiOnsidXNlclByb2ZpbGVEZXRhaWxzIjp7InVzZXJuYW1lIjoiaGFyaW5pMTJ5YXcyMiIsImVtYWlsSWQiOiJtYWhlc2gudGhlbmdAYWxiYW5lcm8uaW8ifX0sInN1YiI6ImhhcmluaTEyeWF3MjIiLCJleHAiOjE2NjczODQ2MjAsImlhdCI6MTY2NzI5ODIyMH0.7jr3dPxsL7_9tPblPzIBUMYwwIi1BLvD9vNavSmVKGjpMSxi3tS9BDxAT3fo6AhB0N5LYRZnnMJPyKa6UMs5aQ"))
//                .thenReturn(true);
//
//        LOGGER.info("Mocking UserRepository");
//        UserProfile userProfile = new UserProfile();
//        userProfile.setId("125");
//        userProfile.setEmailId("username@albanero.io");
//        userProfile.setPassword("$2a$10$ztiANHzDWPpKjABcHtaJSeXJ5AW8ELAy2yhHH1diZgDNyT58YG5ia");
//        Mockito.when(userRepository.findById("125")).thenReturn(Optional.of(userProfile));
//        Mockito.when(userRepository.findByUsername("username")).thenReturn(userProfile);
//        Mockito.when(userRepository.findByEmailId("test@albanero.io")).thenReturn(userProfile);
//        Mockito.when(userRepository.save(userProfile)).thenReturn(userProfile);
//
//        LOGGER.info("Mocking AccStatusRepository");
//        AccountStatus accountStatus = new AccountStatus();
//        AccountApprovalStatus accountApprovalStatus = new AccountApprovalStatus();
//        accountApprovalStatus.setIsAccountApproved(true);
//        accountStatus.setAccountApprovalStatus(accountApprovalStatus);
//        AccountActivationStatus accountActivationStatus = new AccountActivationStatus();
//        accountActivationStatus.setStatusChangedAt(new Date());
//        accountActivationStatus.setStatusChangedBy("123");
//        accountActivationStatus.setIsActive(true);
//        accountStatus.setAccountActivationStatus(accountActivationStatus);
//        Mockito.when(accStatusRepository.findByUserId("125")).thenReturn(accountStatus);
//
//        LOGGER.info("Mocking UserSecRepository");
//        ChangeSecSettings userSec = new ChangeSecSettings();
//        userSec.setResetCode("1895");
//        Mockito.when(userSecRepository.findByUserId("125")).thenReturn(userSec);
//    }
//
//    @Test
//    void changeUserAccountStatus_Block_Test() {
//        try {
//            LOGGER.info("Inside UserControllerTest::changeUserAccountStatus_Block_Test method");
//            UserAccountStatus userAccountStatus = new UserAccountStatus();
//            ArrayList<String> userId = new ArrayList<>();
//            userId.add("125");
//            userAccountStatus.setUserId(userId);
//            userAccountStatus.setIsAccountUnblock(true);
//            userAccountStatus.setIsAccountActivated(true);
//            ResponseEntity<BaseResponse>  response = userController.changeUserAccountStatus(userAccountStatus, request);
//            assertEquals(HttpStatus.OK, response.getStatusCode());
//            assertEquals("Users account status updated Successfully.", response.getBody().getMessage());
//            assertEquals(true, response.getBody().getSuccess());
//            assertEquals("200", response.getBody().getStatusCode());
//        } catch (Exception e) {
//            LOGGER.error("Inside UserControllerTest::changeUserAccountStatus_Block_Test method : Unknown error {} ", e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void changeUserAccountStatus_UserPerformActionOnOwn_Test() {
//        try {
//            LOGGER.info("Inside UserControllerTest::changeUserAccountStatus_UserPerformActionOnOwn_Test method");
//            UserAccountStatus userAccountStatus = new UserAccountStatus();
//            ArrayList<String> userId = new ArrayList<>();
//            userId.add("125");
//            userAccountStatus.setUserId(userId);
//            userAccountStatus.setIsAccountUnblock(true);
//            userAccountStatus.setIsAccountActivated(true);
//            ResponseEntity<BaseResponse>  response = userController.changeUserAccountStatus(userAccountStatus, request);
//            AccountStatusUpdate accountStatusUpdate = (AccountStatusUpdate) response.getBody().getPayload();
//            Object errorUpdatingStatus = accountStatusUpdate.getErrorUpdatingStatus().get(0);
//            String errorReason = (String)  ((HashMap<?, ?>) errorUpdatingStatus).get("reason");
//            assertEquals(HttpStatus.OK, response.getStatusCode());
//            assertEquals("Users account status updated Successfully.", response.getBody().getMessage());
//            assertEquals("200", response.getBody().getStatusCode());
//            assertEquals("User cannot change status of their own account.", errorReason);
//        } catch (Exception e) {
//            LOGGER.error("Inside UserControllerTest::changeUserAccountStatus_UserPerformActionOnOwn_Test method : Unknown error {} ", e.getMessage(), e);
//        }
//    }
//
//    /**
//     * When old password is same as new Password
//     */
//    @Test
//    void setPasswordTest() {
//        try {
//            LOGGER.info("Inside UserControllerTest::setPasswordTest method");
//            ChangePasswordRequest request = new ChangePasswordRequest();
//            request.setToken("5FH4CJ8nydzSs+rDgXUDVCsmNFy4dlmlZ6myuhM8vP6uPEhDqRv+dOlfUQ4LJNVPBitPPCyCKyc69G8vbal/5Zo1wMKAq7lon1lNoY8co2VxLTL5i2qY5ncfcHwsZ8yKV0tsQT9sXE310OlM+TcJI6MmBWIsBL1kajZnksjdUoHqJyOpODG6KBJztIYMP//2zexOqyx1Q9qvZkj4XAif3rBLpf4Lq+NDqQUFsKUGqayEM4sbofaRyAmK8kweN1+hqA2HbbbOH+vPoHGW9L0mIJecITIPP/jfTsaQ5a21CpLil+fgrY6zBi4QLli5RrHTs/Vaa+GdARWDQDLAuYr0z7FUdYiqMNuRJ5EGorfXvmaHMv7dNCqmFIv0jn1i+PCC5flfjBisyhRmz1VsAY12J9zMjrn8xEyBCLUwfKokEu+D2ngCKqx0WlkYZoCuJPLJ");
//            request.setMailId("test@albanero.io");
//            request.setPasscode("1895");
//            request.setNewPassword("Alabnero@01!");
//            request.setConfirmedPassword("Alabnero@01!");
//            ResponseEntity<BaseResponse> response = userController.setPassword(request);
//            assertEquals(HttpStatus.OK, response.getStatusCode());
//            assertEquals("New Password should not be same as old one!", response.getBody().getMessage());
//            assertEquals(false, response.getBody().getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside UserControllerTest::setPasswordTest method : Unknown error {} ", e.getMessage(), e);
//        }
//    }
//}