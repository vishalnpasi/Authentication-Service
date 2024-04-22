//package com.albanero.authenticationservice.controller;
//
//import static org.junit.Assert.assertEquals;
//import static org.mockito.Mockito.doNothing;
//import static org.mockito.Mockito.doThrow;
//import static org.mockito.Mockito.when;
//
//import jakarta.servlet.http.HttpServletRequest;
//
//import com.albanero.authservice.common.util.RequestUtil;
//import org.junit.Before;
//import org.junit.Test;
//import org.junit.runner.RunWith;
//import org.mockito.InjectMocks;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.mockito.MockitoAnnotations;
//import org.powermock.core.classloader.annotations.PowerMockIgnore;
//import org.powermock.modules.junit4.PowerMockRunner;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//
//import com.albanero.authservice.common.dto.request.AuthRequest;
//import com.albanero.authservice.common.dto.request.SecurityQuesRequest;
//import com.albanero.authservice.common.dto.response.AuthResponse;
//import com.albanero.authservice.common.dto.response.BaseResponse;
//import com.albanero.authservice.common.dto.response.FetchResponse;
//import com.albanero.authservice.controller.AuthController;
//import com.albanero.authservice.service.impl.AuthServiceImpl;
//
//@RunWith(PowerMockRunner.class)
//@PowerMockIgnore({ "jakarta.management.*", "jakarta.xml.*", "org.xml.sax.*", "org.w3c.dom.*",
//		"org.springframework.context.*", "org.apache.log4j.*", "org.apache.commons.logging.*", "org.jacoco.*",
//		"jdk.internal.reflect.*" })
//public class AuthControllerTest {
//	private static final Logger LOGGER = LoggerFactory.getLogger(AuthControllerTest.class);
//	private static final String ACCESS_TOKEN = "token.token.token";
//	private static final String REFRESH_TOKEN = "refreshtoken";
//	private static final String USERNAME = "test_username";
//	private static final String PASSWORD = "test_password";
//	private static final String MAILID = "test_mail";
//	private static final String OTP_TOKEN = "test_OTP";
//	private static final String VERIFICATION_CODE = "test_verifiaction";
//	private static final String USERID = "test_Id";
//	private static final String QUESTION = "test_Question";
//	private static final String ANSWER = "test_Answer";
//
//	@Mock
//	private AuthServiceImpl authService;
//
//	@Mock
//	private HttpServletRequest request;
//
//	@Mock
//	private RequestUtil requestUtil;
//
//	@InjectMocks
//	private AuthController authController;
//
//	@Before
//	public void setUp() throws Exception {
//		MockitoAnnotations.initMocks(this);
//	}
//
//	private BaseResponse getBaseResponse() {
//		BaseResponse baseResponse = new BaseResponse();
//		baseResponse.setMessage("Successfully created a User!");
//		baseResponse.setSuccess(true);
//		return baseResponse;
//	}
//
//	private AuthRequest getAuthRequest() {
//		AuthRequest authRequest = new AuthRequest();
//		authRequest.setUsername(USERNAME);
//		authRequest.setPassword(PASSWORD);
//		authRequest.setOtpToken(OTP_TOKEN);
//		authRequest.setVerificationCode(VERIFICATION_CODE);
//		return authRequest;
//	}
//
//	private AuthResponse getAuthResponse() {
//		AuthResponse authResponse = new AuthResponse();
//		authResponse.setMessage("Valid access token generated and returned");
//		authResponse.setSuccess(true);
//		authResponse.setToken(ACCESS_TOKEN);
//		authResponse.setRefreshToken(REFRESH_TOKEN);
//		return authResponse;
//	}
//
//	private SecurityQuesRequest getSecurityQuesRequest() {
//		SecurityQuesRequest secutiryQuesRequest = new SecurityQuesRequest();
//		secutiryQuesRequest.setQuestion(QUESTION);
//		secutiryQuesRequest.setAnswer(ANSWER);
//		return secutiryQuesRequest;
//	}
//
//	private FetchResponse getFetchResponse() {
//		FetchResponse fetchResponse = new FetchResponse();
//		return fetchResponse;
//	}
//
//	@Test
//	public void generateTokenTest_Success() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::generateTokenTest_Success Method");
//			when(authService.generateToken(USERNAME)).thenReturn(getAuthResponse());
//			ResponseEntity<AuthResponse> response = authController.generateToken(USERNAME);
//			assertEquals(true,response.getBody().getSuccess());
//			assertEquals(getAuthResponse(), response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::generateTokenTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void generateTokenTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::generateTokenTest_Failure Method");
//			when(authService.generateToken(Mockito.anyString())).thenThrow(Exception.class);
//			ResponseEntity<AuthResponse> response = authController.generateToken(Mockito.anyString());
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//			assertEquals("Exception Occured while generating access and refresh tokens!",
//					response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::generateTokenTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
////	@Test
////	public void checkForMfaTest_Success() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::checkForMfaTest_Success Method");
////			when(authService.checkForMfa(MAILID)).thenReturn(true);
////			ResponseEntity<Boolean> response = authController.checkForMfa(MAILID);
////			assertEquals(true, response.getBody());
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::checkForMfaTest_Success method : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void checkForMfaTest_Failure() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::checkForMfaTest_Failure Method");
////			when(authService.checkForMfa(Mockito.anyString())).thenThrow(Exception.class);
////			ResponseEntity<Boolean> response = authController.checkForMfa(Mockito.anyString());
////			assertEquals(false, response.getBody());
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::checkForMfaTest_Failure method : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void checkMfaTest_Success() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::checkMfaTest_Success Method");
////			when(authService.checkMfa(request)).thenReturn(true);
////			ResponseEntity<Boolean> response = authController.checkMfa(request);
////			assertEquals(true, response.getBody());
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::checkMfaTest_Success method : Unknown error {} ", e.getMessage(),
////					e);
////		}
////	}
////
////	@Test
////	public void checkMfaTest_Failure() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::checkMfaTest_Failure Method");
////			when(authService.checkMfa(Mockito.<HttpServletRequest>any())).thenThrow(Exception.class);
////			ResponseEntity<Boolean> response = authController.checkMfa(Mockito.<HttpServletRequest>any());
////			assertEquals(false, response.getBody());
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::checkMfaTest_Failure method : Unknown error {} ", e.getMessage(),
////					e);
////		}
////	}
//
////	@Test
////	public void verifyCodeTest_Success() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::verifyCodeTest_Success Method");
////			when(authService.verify(getAuthRequest().getOtpToken(), getAuthRequest().getVerificationCode()))
////					.thenReturn(getBaseResponse());
////			ResponseEntity<BaseResponse> response = authController.verifyCode(getAuthRequest());
////			assertEquals(getBaseResponse(), response.getBody());
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::verifyCodeTest_Success method : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void verifyCodeTest_Failure() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::verifyCodeTest_Failure Method");
////			when(authService.verify(getAuthRequest().getOtpToken(), getAuthRequest().getVerificationCode()))
////					.thenThrow(Exception.class);
////			ResponseEntity<BaseResponse> response = authController.verifyCode(getAuthRequest());
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////			assertEquals("Exception Occured while verifying OTP code for this user!", response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::verifyCodeTest_Failure method : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
//
////	@Test
////	public void generateExternalTokenTest_Failure1() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::generateExternalTokenTest_Failure1 Method");
////			BaseResponse baseResponse = getBaseResponse();
////			when(authService.generateExternalToken(USERID)).thenReturn(baseResponse);
////			baseResponse.setStatusCode("403");
////			ResponseEntity<BaseResponse> response = authController.generateExternalToken(USERID);
////			assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
////			assertEquals(baseResponse, response.getBody());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::generateExternalTokenTest_Failure1 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void generateExternalTokenTest_Sucsess1() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::generateExternalTokenTest_Sucsess1 Method");
////			BaseResponse baseResponse = getBaseResponse();
////			when(authService.generateExternalToken(USERID)).thenReturn(baseResponse);
////			ResponseEntity<BaseResponse> response = authController.generateExternalToken(USERID);
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////			assertEquals(baseResponse, response.getBody());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::generateExternalTokenTest_Sucsess1 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void generateExternalTokenTest_Failure2() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::generateExternalTokenTest_Failure2 Method");
////			when(authService.generateExternalToken(Mockito.anyString())).thenThrow(Exception.class);
////			ResponseEntity<BaseResponse> response = authController.generateExternalToken(Mockito.anyString());
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////			assertEquals("Exception occured in generating external token!", response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::generateExternalTokenTest_Failure2 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
//
////	@Test
////	public void createAuthenticationTokenTest_Failure1() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::createAuthenticationTokenTest_Failure1 Method");
////			BaseResponse baseResponse = getBaseResponse();
////			when(authService.authenticate(request, getAuthRequest())).thenReturn(baseResponse);
////			baseResponse.setStatusCode("401");
////			ResponseEntity<BaseResponse> response = authController.createAuthenticationToken(request, getAuthRequest());
////			assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
////			assertEquals(baseResponse, response.getBody());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::createAuthenticationTokenTest_Failure1 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void createAuthenticationTokenTest_Failure2() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::createAuthenticationTokenTest_Failure2 Method");
////			BaseResponse baseResponse = getBaseResponse();
////			when(authService.authenticate(request, getAuthRequest())).thenReturn(baseResponse);
////			baseResponse.setStatusCode("403");
////			ResponseEntity<BaseResponse> response = authController.createAuthenticationToken(request, getAuthRequest());
////			assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
////			assertEquals(baseResponse, response.getBody());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::createAuthenticationTokenTest_Failure2 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void createAuthenticationTokenTest_Failure3() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::createAuthenticationTokenTest_Failure3 Method");
////			BaseResponse baseResponse = getBaseResponse();
////			when(authService.authenticate(request, getAuthRequest())).thenReturn(baseResponse);
////			baseResponse.setStatusCode("500");
////			ResponseEntity<BaseResponse> response = authController.createAuthenticationToken(request, getAuthRequest());
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////			assertEquals(baseResponse, response.getBody());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::createAuthenticationTokenTest_Failure3 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void createAuthenticationTokenTest_Sucsess1() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::createAuthenticationTokenTest_Sucsess1 Method");
////			BaseResponse baseResponse = getBaseResponse();
////			when(authService.authenticate(request, getAuthRequest())).thenReturn(baseResponse);
////			ResponseEntity<BaseResponse> response = authController.createAuthenticationToken(request, getAuthRequest());
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////			assertEquals(baseResponse, response.getBody());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::createAuthenticationTokenTest_Sucsess1 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void createAuthenticationTokenTest_Failure4() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::createAuthenticationTokenTest_Failure4 Method");
////			when(authService.authenticate(Mockito.<HttpServletRequest>any(), Mockito.<AuthRequest>any()))
////					.thenThrow(DisabledException.class);
////			ResponseEntity<BaseResponse> response = authController
////					.createAuthenticationToken(Mockito.<HttpServletRequest>any(), Mockito.<AuthRequest>any());
////			assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
////			assertEquals("User disabled exception Occured while validating authentication token!",
////					response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::createAuthenticationTokenTest_Failure4 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void createAuthenticationTokenTest_Failure5() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::createAuthenticationTokenTest_Failure5 Method");
////			when(authService.authenticate(Mockito.<HttpServletRequest>any(), Mockito.<AuthRequest>any()))
////					.thenThrow(BadCredentialsException.class);
////			ResponseEntity<BaseResponse> response = authController
////					.createAuthenticationToken(Mockito.<HttpServletRequest>any(), Mockito.<AuthRequest>any());
////			assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
////			assertEquals("Bad Credentials exception Occured while validating authentication token!",
////					response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::createAuthenticationTokenTest_Failure5 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void createAuthenticationTokenTest_Failure6() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::createAuthenticationTokenTest_Failure Method");
////			when(authService.authenticate(Mockito.<HttpServletRequest>any(), Mockito.<AuthRequest>any()))
////					.thenThrow(Exception.class);
////			ResponseEntity<BaseResponse> response = authController
////					.createAuthenticationToken(Mockito.<HttpServletRequest>any(), Mockito.<AuthRequest>any());
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////			assertEquals("Exception Occured while validating authentication token!", response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::createAuthenticationTokenTest_Failure6 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
//
//	@Test
//	public void validateAccessTokenTest_Failure1() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::validateAccessTokenTest_Failure1 Method");
//			BaseResponse baseResponse = getBaseResponse();
//			when(authService.validateAccessToken(request)).thenReturn(baseResponse);
//			baseResponse.setStatusCode("403");
//			ResponseEntity<BaseResponse> response = authController.validateAccessToken(request);
//			assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
//			assertEquals(baseResponse, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::validateAccessTokenTest_Failure1 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateAccessTokenTest_Failure2() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::validateAccessTokenTest_Failure2 Method");
//			BaseResponse baseResponse = getBaseResponse();
//			when(authService.validateAccessToken(request)).thenReturn(baseResponse);
//			baseResponse.setStatusCode("400");
//			ResponseEntity<BaseResponse> response = authController.validateAccessToken(request);
//			assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
//			assertEquals(baseResponse, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::validateAccessTokenTest_Failure2 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateAccessTokenTest_Failure3() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::validateAccessTokenTest_Failure3 Method");
//			BaseResponse baseResponse = getBaseResponse();
//			when(authService.validateAccessToken(request)).thenReturn(baseResponse);
//			baseResponse.setStatusCode("401");
//			ResponseEntity<BaseResponse> response = authController.validateAccessToken(request);
//			assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
//			assertEquals(baseResponse, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::validateAccessTokenTest_Failure3 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateAccessTokenTest_Sucsess1() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::validateAccessTokenTest_Sucsess1 Method");
//			BaseResponse baseResponse = getBaseResponse();
//			when(authService.validateAccessToken(request)).thenReturn(baseResponse);
//			ResponseEntity<BaseResponse> response = authController.validateAccessToken(request);
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//			assertEquals(baseResponse, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::validateAccessTokenTest_Sucsess1 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateAccessTokenTest_Failure4() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::validateAccessTokenTest_Failure4 Method");
//			when(authService.validateAccessToken(Mockito.<HttpServletRequest>any())).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = authController
//					.validateAccessToken(Mockito.<HttpServletRequest>any());
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//			assertEquals("Exception occured while validating auth token.", response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::validateAccessTokenTest_Failure4 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//
//
////	@Test
////	public void getSecurityQuestionTest_Failure1() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::getSecurityQuestionTest_Failure1 Method");
////			BaseResponse baseResponse = getBaseResponse();
////			when(authService.getSecurityQuestion(USERNAME)).thenReturn(baseResponse);
////			baseResponse.setStatusCode("403");
////			ResponseEntity<BaseResponse> response = authController.getSecurityQuestion(USERNAME);
////			assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
////			assertEquals(baseResponse, response.getBody());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::getSecurityQuestionTest_Failure1 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void getSecurityQuestionTest_Sucsess1() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::getSecurityQuestionTest_Sucsess1 Method");
////			BaseResponse baseResponse = getBaseResponse();
////			when(authService.getSecurityQuestion(USERNAME)).thenReturn(baseResponse);
////			ResponseEntity<BaseResponse> response = authController.getSecurityQuestion(USERNAME);
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////			assertEquals(baseResponse, response.getBody());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::getSecurityQuestionTest_Sucsess1 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void getSecurityQuestionTest_Failure2() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::getSecurityQuestionTest_Failure2 Method");
////			when(authService.getSecurityQuestion(Mockito.anyString())).thenThrow(Exception.class);
////			ResponseEntity<BaseResponse> response = authController.getSecurityQuestion(Mockito.anyString());
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////			assertEquals("Exception occured in getting security question!", response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::getSecurityQuestionTest_Failure2 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
//
//
//
//	@Test
//	public void getSecurityQuestionsTest_Sucsess1() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::getSecurityQuestionsTest_Sucsess1 Method");
//			BaseResponse baseResponse = getBaseResponse();
//			when(authService.getSecurityQuestions()).thenReturn(baseResponse);
//			ResponseEntity<BaseResponse> response = authController.getSecurityQuestions();
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//			assertEquals(baseResponse, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::getSecurityQuestionsTest_Sucsess1 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getSecurityQuestionsTest_Failure1() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::getSecurityQuestionsTest_Failure1 Method");
//			BaseResponse baseResponse = getBaseResponse();
//			when(authService.getSecurityQuestions()).thenReturn(baseResponse);
//			baseResponse.setStatusCode("403");
//			ResponseEntity<BaseResponse> response = authController.getSecurityQuestions();
//			assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
//			assertEquals(baseResponse, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::getSecurityQuestionsTest_Failure1 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getSecurityQuestionsTest_Failure2() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::getSecurityQuestionsTest_Failure2 Method");
//			when(authService.getSecurityQuestions()).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = authController.getSecurityQuestions();
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//			assertEquals("Exception occured in getting security questions!", response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::getSecurityQuestionsTest_Failure2 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//
//	@Test
//	public void saveSecurityQuestionsTest_Success() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::saveSecurityQuestionsTest_Sucsess1 Method");
//			BaseResponse baseResponse = getBaseResponse();
//			when(authService.saveSecurityQuestion(request, getSecurityQuesRequest())).thenReturn(baseResponse);
//			ResponseEntity<BaseResponse> response = authController.saveSecurityQuestions(request,
//					getSecurityQuesRequest());
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//			assertEquals(baseResponse, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::saveSecurityQuestionsTest_Sucsess1 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveSecurityQuestionsTest_Failure1() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::saveSecurityQuestionsTest_Failure1 Method");
//			BaseResponse baseResponse = getBaseResponse();
//			when(authService.saveSecurityQuestion(request, getSecurityQuesRequest())).thenReturn(baseResponse);
//			baseResponse.setStatusCode("403");
//			ResponseEntity<BaseResponse> response = authController.saveSecurityQuestions(request,
//					getSecurityQuesRequest());
//			assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
//			assertEquals(baseResponse, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::saveSecurityQuestionsTest_Failure1 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveSecurityQuestionsTest_Failure2() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::saveSecurityQuestionsTest_Failure2 Method");
//			when(authService.saveSecurityQuestion(Mockito.<HttpServletRequest>any(),
//					Mockito.<SecurityQuesRequest>any())).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = authController
//					.saveSecurityQuestions(Mockito.<HttpServletRequest>any(), Mockito.<SecurityQuesRequest>any());
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//			assertEquals("Exception occured in saving security question!", response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::saveSecurityQuestionsTest_Failure2 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkSecurityQuestionTest_Sucsess() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::checkSecurityQuestionTest_Sucsess Method");
//			BaseResponse baseResponse = getBaseResponse();
//			when(authService.checkSecurityQuestion("USERNAME",getSecurityQuesRequest())).thenReturn(baseResponse);
//			ResponseEntity<BaseResponse> response = authController.checkSecurityQuestion("USERNAME",
//					getSecurityQuesRequest());
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//			assertEquals(baseResponse, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::checkSecurityQuestionTest_Sucsess : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkSecurityQuestionTest_Failure1() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::checkSecurityQuestionTest_Failure Method");
//			when(authService.checkSecurityQuestion(Mockito.anyString(), Mockito.<SecurityQuesRequest>any()))
//					.thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = authController.checkSecurityQuestion("USERNAME",
//					getSecurityQuesRequest());
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//			assertEquals("Exception occured in getting security questions!", response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::checkSecurityQuestionTest_Failure : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkSecurityQuestionTest_Failure2() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::checkSecurityQuestionTest_Failure1 Method");
//			BaseResponse baseResponse = getBaseResponse();
//			when(authService.checkSecurityQuestion("USERNAME",getSecurityQuesRequest())).thenReturn(baseResponse);
//			baseResponse.setStatusCode("403");
//			ResponseEntity<BaseResponse> response = authController.checkSecurityQuestion("USERNAME",
//					getSecurityQuesRequest());
//			assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
//			assertEquals(baseResponse, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::checkSecurityQuestionTest_Failure1 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//
//	@Test
//	public void checkForSecurityQuestionsTest_Success()
//	{
//		try {
//			LOGGER.debug("Inside LoginControllerTest::checkForSecurityQuestionsTest_Success Method");
//			BaseResponse baseResponse = getBaseResponse();
//			when(authService.checkForSQ("username")).thenReturn(baseResponse);
//			ResponseEntity<BaseResponse> response = authController.checkForSecurityQuestions("username");
//			assertEquals(baseResponse, response.getBody());
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::checkForSecurityQuestionsTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkForSecurityQuestionsTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::checkForSecurityQuestionsTest_Failure Method");
//			BaseResponse baseResponse = new BaseResponse();
//			when(authService.checkForSQ(Mockito.anyString())).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = authController.checkForSecurityQuestions(Mockito.anyString());
//			assertEquals(baseResponse, response.getBody());
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::checkForSecurityQuestionsTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//
//	@Test
//	public void checkSQEnable_Success() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::checkSQEnableTest_Success Method");
//			when(authService.checkSQ(request)).thenReturn(true);
//			ResponseEntity<Boolean> response = authController.checkSQEnable(request);
//			assertEquals(true, response.getBody());
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::checkSQEnableTest_Success method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void checkSQEnableTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::checkSQEnableTest_Failure Method");
//			when(authService.checkSQ(Mockito.<HttpServletRequest>any())).thenThrow(Exception.class);
//			ResponseEntity<Boolean> response = authController.checkSQEnable(Mockito.<HttpServletRequest>any());
//			assertEquals(false, response.getBody());
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::checkSQEnableTest_Failure method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//
//
//	@Test
//	public void invalidateTokenTest_Success() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::invalidateTokenTest_Success Method");
//			doNothing().when(authService).invalidateExistingRefreshToken(USERNAME);
//			ResponseEntity<BaseResponse> response = authController.invalidateToken(request, USERNAME);
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//			assertEquals("Token has been invalidated.", response.getBody().getMessage());
//			assertEquals(true, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::invalidateTokenTest_Success : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void invalidateTokenTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::invalidateTokenTest_Failure Method");
//			doThrow(Exception.class).when(authService).invalidateExistingRefreshToken(USERNAME);
//			ResponseEntity<BaseResponse> response = authController.invalidateToken(request, USERNAME);
//			System.out.println(response.getBody());
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//			assertEquals("Exception Occured while invalidating refresh token!", response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::invalidateTokenTest_Failure : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void isRefreshTokenValidTest_Failure1() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::isRefreshTokenValidTest_Failure1 Method");
//			when(requestUtil.isRTPresent(ACCESS_TOKEN)).thenReturn(false);
//			ResponseEntity<BaseResponse> response = authController.isRefreshTokenValid(ACCESS_TOKEN);
//			assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
//			assertEquals("You have been logged out!", response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::isRefreshTokenValidTest_Failure1 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void isRefreshTokenValidTest_Sucsess1() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::isRefreshTokenValidTest_Sucsess1 Method");
//			when(requestUtil.isRTPresent(ACCESS_TOKEN)).thenReturn(true);
//			when(requestUtil.validateRefreshToken(ACCESS_TOKEN)).thenReturn(true);
//			ResponseEntity<BaseResponse> response = authController.isRefreshTokenValid(ACCESS_TOKEN);
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//			assertEquals("Refresh Token is valid.", response.getBody().getMessage());
//			assertEquals(true, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::isRefreshTokenValidTest_Sucsess1 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void isRefreshTokenValidTest_Failure2() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::isRefreshTokenValidTest_Failure2 Method");
//			when(requestUtil.isRTPresent(ACCESS_TOKEN)).thenReturn(true);
//			when(requestUtil.validateRefreshToken(ACCESS_TOKEN)).thenReturn(false);
//			ResponseEntity<BaseResponse> response = authController.isRefreshTokenValid(ACCESS_TOKEN);
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//			assertEquals("Refresh Token is invalid.", response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::isRefreshTokenValidTest_Failure2 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void isRefreshTokenValidTest_Failure3() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::isRefreshTokenValidTest_Failure3 Method");
//			when(requestUtil.isRTPresent(ACCESS_TOKEN)).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = authController.isRefreshTokenValid(ACCESS_TOKEN);
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//			assertEquals("Exception Occured while validating refresh token!", response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::isRefreshTokenValidTest_Failure3 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
////	@Test
////	public void securityChecksTest_Failure1() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::securityChecksTest_Failure1 Method");
////			when(authService.securityChecks(USERNAME)).thenThrow(Exception.class);
////			ResponseEntity<BaseResponse> response = authController.securityChecks(USERNAME);
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////			assertEquals("Exception Occured while validating authentication token!", response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::securityChecksTest_Failure1 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void securityChecksTest_Failure2() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::securityChecksTest_Failure2 Method");
////			BaseResponse baseResponse = getBaseResponse();
////			baseResponse.setMessage("User doesn't exist.");
////			baseResponse.setSuccess(false);
////			when(authService.securityChecks(USERNAME)).thenReturn(baseResponse);
////			ResponseEntity<BaseResponse> response = authController.securityChecks(USERNAME);
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////			assertEquals("User doesn't exist.", response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::securityChecksTest_Failure2 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void securityChecksTest_Success() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::securityChecksTest_Success Method");
////			BaseResponse baseResponse = getBaseResponse();
////			when(authService.securityChecks(USERNAME)).thenReturn(baseResponse);
////			ResponseEntity<BaseResponse> response = authController.securityChecks(USERNAME);
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////			assertEquals(true, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::securityChecksTest_Success : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
//
////	@Test
////	public void logoutTest_Success() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::logoutTest_Success Method");
////			when(authService.logout(request)).thenReturn(getBaseResponse());
////			ResponseEntity<BaseResponse> response = authController.logout(request);
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////			assertEquals("User logged out!", response.getBody().getMessage());
////			assertEquals(true, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::logoutTest_Success method : Unknown error {} ", e.getMessage(),
////					e);
////		}
////	}
////
////	@Test
////	public void logoutTest_Failure() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::logoutTest_Failure Method");
////			when(authService.logout(request)).thenThrow(Exception.class);
////			ResponseEntity<BaseResponse> response = authController.logout(request);
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////			assertEquals("Exception occured while logging out the user!", response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::logoutTest_Failure method : Unknown error {} ", e.getMessage(),
////					e);
////		}
////	}
////
////	@Test
////	public void isTokenValidTest_Sucsess1() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::isTokenValidTest_Sucsess1 Method");
////			when(authService.isTokenValid(request, ACCESS_TOKEN)).thenReturn(true);
////			ResponseEntity<BaseResponse> response = authController.isTokenValid(request, ACCESS_TOKEN);
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////			assertEquals("Token is valid.", response.getBody().getMessage());
////			assertEquals(true, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::isRefreshTokenValidTest_Sucsess1 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void isTokenValidTest_Failure1() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::isTokenValidTest_Failure1 Method");
////			when(authService.isTokenValid(request, ACCESS_TOKEN)).thenReturn(false);
////			ResponseEntity<BaseResponse> response = authController.isTokenValid(request, ACCESS_TOKEN);
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////			assertEquals("Token is invalid.", response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::isRefreshTokenValidTest_Failure1 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void isTokenValidTest_Failure2() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::isTokenValidTest_Failure2 Method");
////			when(authService.isTokenValid(request, ACCESS_TOKEN)).thenThrow(Exception.class);
////			ResponseEntity<BaseResponse> response = authController.isTokenValid(request, ACCESS_TOKEN);
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////			assertEquals("Exception Occured while validating authentication token!", response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::isRefreshTokenValidTest_Failure2 : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
//
//}