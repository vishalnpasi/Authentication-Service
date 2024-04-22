//package com.albanero.authservice.service;
//
//import com.albanero.authservice.common.dto.request.AuthRequest;
//import com.albanero.authservice.common.dto.request.AuthenticationRequest;
//import com.albanero.authservice.common.dto.response.BaseResponse;
//import com.albanero.authservice.common.dto.response.FetchResponse;
//import com.albanero.authservice.common.util.RequestUtil;
//import com.albanero.authservice.model.*;
//import com.albanero.authservice.repository.AccStatusRepository;
//import com.albanero.authservice.repository.UserRepository;
//import com.albanero.authservice.repository.UserSessionRepository;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.boot.test.mock.mockito.MockBean;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//
//import jakarta.servlet.http.HttpServletRequest;
//
//import java.util.ArrayList;
//import java.util.HashMap;
//import java.util.List;
//
//import static org.junit.jupiter.api.Assertions.*;
//import static org.mockito.Mockito.when;
//
//@SpringBootTest
//class AuthenticationServiceTest {
//
//    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationServiceTest.class);
//
//    @Autowired
//    private AuthenticationService authenticationService;
//
//    @MockBean
//    private HttpServletRequest request;
//
//    @MockBean
//    private RequestUtil requestUtil;
//
//    @MockBean
//    private AuthenticationManager authenticationManager;
//
//    @MockBean
//    private UserRepository userRepository;
//
//    @MockBean
//    private AccStatusRepository accStatusRepository;
//
//    @MockBean
//    private UserSessionRepository userSessionRepository;
//
//    @BeforeEach
//    public void mockingService() throws Exception {
//        String token = "\"+T9GQAISo/+9D95DlKfFuDmR7AYUxKjAAkmK3mrWhPf5BqtRXxyz/Hgz1jvPxtIHGtWeBcyln8qyBSQT3qF3l6j6LFFMPmj7J/ShwmDUzsY+RG7/qFWsr3EDgXzLE3lQ9RNkdSGBzwjVZokUVpRnNwIoljWU9Ixvsh6HJKydYUL9G/yO1e2Aqci1jdTXSlbZI9HD88uficKiYS9ClzyrIe/iP0WL17XVofw6+7h2/NO19afChGBCvGn8v2vFNStbP5Woj1/gKGD43GwYw7CyQPnO8L7WlKseLTxuaHarulUKkEGJW6/1WaGPhwYZFv71fNyrLbUklOOg+xJkl68veC0V11ZoNLKq5YW3XNDu51kzL88LxFWlNe/WA52p9+iqqTwNK0giipHdEdCuW2uFkq3cLGzYSDKufAlUxtruWVXJeZdg0/O8eg==";
//        FetchResponse requestDetails = new FetchResponse();
//        when(requestUtil.fetchRequestDetails(request)).thenReturn(requestDetails);
//        when(requestUtil.extractRtFromRequest(request)).thenReturn("refreshToken");
//        when(requestUtil.isRefreshToken("refreshToken")).thenReturn(false);
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
//        when(requestUtil.extractJwtFromRequest(request)).thenReturn(token);
//        when(requestUtil.validateTokenFromTokenService(token)).thenReturn(true);
//        when(requestUtil.usernameFromToken(token)).thenReturn("username");
//
//        when(authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("username", "pass"))).thenReturn(null);
//
//        UserProfile userProfile = new UserProfile();
//        userProfile.setId("125");
//        when(userRepository.findByUsername("username")).thenReturn(userProfile);
//
//        LOGGER.info("Mocking AccStatusRepository");
//        AccountStatus accountStatus = new AccountStatus();
//        AccountApprovalStatus accountApprovalStatus = new AccountApprovalStatus();
//        accountApprovalStatus.setIsAccountApproved(true);
//        accountStatus.setAccountApprovalStatus(accountApprovalStatus);
//        AccountActivationStatus accountActivationStatus = new AccountActivationStatus();
//        accountActivationStatus.setIsActive(true);
//        accountStatus.setAccountActivationStatus(accountActivationStatus);
//        EmailStatus emailStatus = new EmailStatus();
//        emailStatus.setIsVerified(true);
//        accountStatus.setEmailStatus(emailStatus);
//        when(accStatusRepository.findByUserId("125")).thenReturn(accountStatus);
//
//        UserSession userSession = new UserSession();
//        userSession.setEncryptedRT("145");
//        userSession.setHashedRT("154");
//        when(userSessionRepository.findByUserId("125")).thenReturn(userSession);
//
//    }
//
//    /**
//     * When User IP is Block
//     */
//    @Test
//    void authenticateTest() throws Exception {
//        try {
//            LOGGER.info("Inside AuthenticationServiceTest::authenticateTest method");
//            AuthRequest authRequest = new AuthRequest();
//            authRequest.setUsername("username");
//            authRequest.setPassword("pass");
//            BaseResponse response = authenticationService.authenticate(request, authRequest);
//            assertEquals(false, response.getSuccess());
//            assertEquals("User can't Login because this IP is blocked!", response.getMessage());
//            assertEquals("403", response.getStatusCode());
//        } catch (Exception e) {
//            LOGGER.error("Inside AuthenticationServiceTest::authenticateTest method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    /**
//     * When User IP is Block
//     */
//    @Test
//    void validateAccessTokenTest() {
//        try {
//            LOGGER.info("Inside AuthenticationServiceTest::validateAccessTokenTest method");
//            BaseResponse response = authenticationService.validateAccessToken(request);
//            assertEquals(false, response.getSuccess());
//            assertEquals("User can't Authentication because this IP is blocked!", response.getMessage());
//            assertEquals("403", response.getStatusCode());
//        } catch (Exception e) {
//            LOGGER.error("Inside AuthenticationServiceTest::validateAccessTokenTest method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void authenticateOtpPasscode_Test(){
//        try {
//            LOGGER.info("Inside AuthenticationServiceTest::authenticateOtpPasscode_Test method");
//            BaseResponse response = authenticationService.authenticateOtpPasscode(request,"test@gmail.com","233234");
//            assertEquals(false, response.getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside AuthenticationServiceTest::authenticateOtpPasscode_Test method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//
//    @Test
//    void checkForPassword_Test(){
//        try {
//            LOGGER.info("Inside AuthenticationServiceTest::checkForPassword_Test method");
//            BaseResponse response = authenticationService.checkForPassword(request,"Passd@12345");
//            assertEquals(true, response.getSuccess());
//        } catch (Exception e) {
//            LOGGER.error("Inside AuthenticationServiceTest::checkForPassword_Test method : Unknown error {} ",
//                    e.getMessage(), e);
//        }
//    }
//}