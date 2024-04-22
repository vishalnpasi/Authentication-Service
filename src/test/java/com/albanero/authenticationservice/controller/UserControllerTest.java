//package com.albanero.authenticationservice.controller;
//
//import static org.junit.Assert.assertEquals;
//import static org.mockito.Mockito.when;
//
//import java.util.ArrayList;
//
//import jakarta.servlet.http.HttpServletRequest;
//
//import com.albanero.authservice.common.util.HelperUtil;
//import com.albanero.authservice.repository.UserRepository;
//import com.albanero.authservice.service.UserService;
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
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//
//import com.albanero.authservice.common.dto.request.AuthRequest;
//import com.albanero.authservice.common.dto.request.ChangePasswordRequest;
//import com.albanero.authservice.common.dto.request.PasswordCheckRequest;
//import com.albanero.authservice.common.dto.request.RegistrationUser;
//import com.albanero.authservice.common.dto.response.BaseResponse;
//import com.albanero.authservice.common.dto.response.ResetPasswordResponse;
//import com.albanero.authservice.controller.UserController;
//import com.albanero.authservice.model.Organization;
//import com.albanero.authservice.model.UserProfile;
//import com.albanero.authservice.service.impl.AuthServiceImpl;
//
//@RunWith(PowerMockRunner.class)
//@PowerMockIgnore({ "jakarta.management.*", "jakarta.xml.*", "org.xml.sax.*", "org.w3c.dom.*",
//		"org.springframework.context.*", "org.apache.log4j.*", "org.apache.commons.logging.*", "org.jacoco.*",
//		"jdk.internal.reflect.*" })
//public class UserControllerTest {
//	private static final Logger LOGGER = LoggerFactory.getLogger(AuthControllerTest.class);
//	private static final String USERNAME = "test_username";
//	private static final String MAILID = "test_mail";
//	private static final String USERID = "test_Id";
//	private static final String ORG_NAME = "test_Organization";
//	private static final String ORG_ID = "test_orgId";
//	private static final String PRODUCT_ID = "test_productId";
//	private static final String ROLE = "test_Role";
//	private static final String PASSWORD = "test_password";
//
//	@Mock
//	private AuthServiceImpl authService;
//
//	@Mock
//	private HelperUtil helperUtil;
//
//	@Mock
//	private UserService userService;
//
//	@Mock
//	private HttpServletRequest request;
//	@InjectMocks
//	private UserController userController;
//
//	@Before
//	public void setUp() throws Exception {
//		MockitoAnnotations.initMocks(this);
//	}
//
//	@Mock
//	private UserRepository userRepo;
//
//	private BaseResponse getBaseResponse() {
//		BaseResponse baseResponse = new BaseResponse();
//		baseResponse.setMessage("Successfully created a User!");
//		baseResponse.setSuccess(true);
//		return baseResponse;
//	}
//
////	public AddMemberRequest getAddMemberRequest() {
////		AddMemberRequest addMemberRequest = new AddMemberRequest();
////		addMemberRequest.setOrgId(ORG_ID);
////		addMemberRequest.setProdId(PRODUCT_ID);
////		addMemberRequest.setRole(ROLE);
////		addMemberRequest.setUsername(USERNAME);
////		return addMemberRequest;
////	}
//
//	private UserDetails getUserDetails() {
//		AuthRequest user = new AuthRequest();
//		user.setPassword(PASSWORD);
//		user.setUsername(USERNAME);
//		return new User(user.getUsername(), user.getPassword(), new ArrayList<>());
//	}
//
//	private RegistrationUser getRegistrationUser() {
//
//		RegistrationUser registrationUser = new RegistrationUser();
//		return registrationUser;
//	}
//
//	private UserProfile getDaoUser() {
//		UserProfile userProfile = new UserProfile();
//		return userProfile;
//	}
//
//	private PasswordCheckRequest getPasswordCheckRequest() {
//		PasswordCheckRequest passwordCheckRequest = new PasswordCheckRequest();
//		passwordCheckRequest.setCurrentPassword(PASSWORD);
//		return passwordCheckRequest;
//	}
//
//	@Test
//	public void fetchEmailTest_Sucsess1() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::fetchEmailTest_Sucsess1 Method");
//			when(userService.fetchEmail(request)).thenReturn(MAILID);
//			ResponseEntity<BaseResponse> response = userController.fetchEmail(request);
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//			assertEquals("Successfully fetched email.", response.getBody().getMessage());
//			assertEquals(true, response.getBody().getSuccess());
//			assertEquals(MAILID, response.getBody().getPayload());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::fetchEmailTest_Sucsess1 : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void fetchEmailTest_Failure1() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::fetchEmailTest_Failure1 Method");
//			when(userService.fetchEmail(request)).thenReturn(null);
//			ResponseEntity<BaseResponse> response = userController.fetchEmail(request);
//			assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
//			assertEquals("Email does not exist for this user!", response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::fetchEmailTest_Failure1 : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void fetchEmailTest_Failure2() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::fetchEmailTest_Failure2 Method");
//			when(userService.fetchEmail(Mockito.<HttpServletRequest>any())).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController.fetchEmail(Mockito.<HttpServletRequest>any());
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//			assertEquals("Email does not exist for this user!", response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::fetchEmailTest_Failure2 : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getAllProductDetailsTest_Sucsess() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::getAllProductDetailsTest_Sucsess Method");
//			when(userService.getProductDetails(request)).thenReturn(getBaseResponse());
//			ResponseEntity<BaseResponse> response = userController.getAllProductDetails(request);
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//			assertEquals(getBaseResponse(), response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::getAllProductDetailsTest_Sucsess : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getAllProductDetailsTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::getAllProductDetailsTest_Failure Method");
//			when(userService.getProductDetails(Mockito.<HttpServletRequest>any())).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController
//					.getAllProductDetails(Mockito.<HttpServletRequest>any());
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//			assertEquals("Exception Occured while fetching product details!", response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::getAllProductDetailsTest_Failure : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void fetchUsernameTest_Failure1() {
//		try {
//			BaseResponse baseResponse = getBaseResponse();
//			LOGGER.debug("Inside LoginControllerTest::fetchUsernameTest_Failure1 Method");
//			when(userService.fetchUsername(request, USERID)).thenReturn(baseResponse);
//			baseResponse.setStatusCode("403");
//			ResponseEntity<BaseResponse> response = userController.fetchUsername(request, USERID);
//			assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
//			assertEquals(baseResponse, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::fetchUsernameTest_Failure1 : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void fetchUsernameTest_Sucsess1() {
//		try {
//			BaseResponse baseResponse = getBaseResponse();
//			LOGGER.debug("Inside LoginControllerTest::fetchUsernameTest_Sucsess1 Method");
//			when(userService.fetchUsername(request, USERID)).thenReturn(baseResponse);
//			ResponseEntity<BaseResponse> response = userController.fetchUsername(request, USERID);
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//			assertEquals(baseResponse, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::fetchUsernameTest_Sucsess1 : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void fetchUsernameTest_Failure2() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::fetchUsernameTest_Failure2 Method");
//			when(userService.fetchUsername(Mockito.<HttpServletRequest>any(), Mockito.anyString()))
//					.thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController.fetchUsername(Mockito.<HttpServletRequest>any(),
//					Mockito.anyString());
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//			assertEquals("Exception occured while fetching username.", response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::fetchUsernameTest_Failure2 : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
////	@Test
////	public void createOrganizationTest_Sucsess() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::createOrganizationTest_Sucsess Method");
////			when(authService.createOrganization(request, ORG_NAME)).thenReturn(getBaseResponse());
////			ResponseEntity<BaseResponse> response = userController.createOrganization(request, ORG_NAME);
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////			assertEquals(getBaseResponse(), response.getBody());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::createOrganizationTest_Sucsess : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void createOrganizationTest_Failure() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::createOrganizationTest_Failure Method");
////			when(authService.createOrganization(Mockito.<HttpServletRequest>any(), Mockito.anyString()))
////					.thenThrow(Exception.class);
////			ResponseEntity<BaseResponse> response = userController.createOrganization(Mockito.<HttpServletRequest>any(),
////					Mockito.anyString());
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////			assertEquals("Exception Occured while creating organization!", response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::createOrganizationTest_Failure : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void updateOrganizationTest_Sucsess() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::updateOrganizationTest_Sucsess Method");
////			when(authService.updateOrganization(request, ORG_NAME)).thenReturn(getBaseResponse());
////			ResponseEntity<BaseResponse> response = userController.updateOrganization(request, ORG_NAME);
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////			assertEquals(getBaseResponse(), response.getBody());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::updateOrganizationTest_Sucsess : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void updateOrganizationTest_Failure() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::updateOrganizationTest_Failure Method");
////			when(authService.updateOrganization(Mockito.<HttpServletRequest>any(), Mockito.anyString()))
////					.thenThrow(Exception.class);
////			ResponseEntity<BaseResponse> response = userController.updateOrganization(Mockito.<HttpServletRequest>any(),
////					Mockito.anyString());
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////			assertEquals("Exception Occured while updating organization!", response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::updateOrganizationTest_Failure : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
//
////	@Test
////	public void removeProductMemberTest_Sucsess() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::removeProductMemberTest_Sucsess Method");
////			when(authService.removeProductMember(request, getAddMemberRequest())).thenReturn(getBaseResponse());
////			ResponseEntity<BaseResponse> response = userController.removeProductMember(request, getAddMemberRequest());
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////			assertEquals(getBaseResponse(), response.getBody());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::removeProductMemberTest_Sucsess : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void removeProductMemberTest_Failure() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::removeProductMemberTest_Failure Method");
////			when(authService.removeProductMember(Mockito.<HttpServletRequest>any(), Mockito.<AddMemberRequest>any()))
////					.thenThrow(Exception.class);
////			ResponseEntity<BaseResponse> response = userController
////					.removeProductMember(Mockito.<HttpServletRequest>any(), Mockito.<AddMemberRequest>any());
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////			assertEquals("Exception Occured while removing organization member!", response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::removeProductMemberTest_Failure : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void addProductMemberTest_Sucsess() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::addProductMemberTest_Sucsess Method");
////			when(authService.addProductMember(request, getAddMemberRequest())).thenReturn(getBaseResponse());
////			ResponseEntity<BaseResponse> response = userController.addProductMember(request, getAddMemberRequest());
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////			assertEquals(getBaseResponse(), response.getBody());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::addProductMemberTest_Sucsess : Unknown error {} ", e.getMessage(),
////					e);
////		}
////	}
////
////	@Test
////	public void addProductMemberTest_Failure() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::addProductMemberTest_Failure Method");
////			when(authService.addProductMember(Mockito.<HttpServletRequest>any(), Mockito.<AddMemberRequest>any()))
////					.thenThrow(Exception.class);
////			ResponseEntity<BaseResponse> response = userController.addProductMember(Mockito.<HttpServletRequest>any(),
////					Mockito.<AddMemberRequest>any());
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////			assertEquals("Exception Occured while adding organization member!", response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::addProductMemberTest_Failure : Unknown error {} ", e.getMessage(),
////					e);
////		}
////	}
//
////	@Test
////	public void removeOrgMemberTest_Sucsess() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::removeOrgMemberTest_Sucsess Method");
////			when(authService.removeOrgMember(request, getAddMemberRequest())).thenReturn(getBaseResponse());
////			ResponseEntity<BaseResponse> response = userController.removeOrgMember(request, getAddMemberRequest());
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////			assertEquals(getBaseResponse(), response.getBody());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::removeOrgMemberTest_Sucsess : Unknown error {} ", e.getMessage(),
////					e);
////		}
////	}
////
////	@Test
////	public void removeOrgMemberTest_Failure() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::removeOrgMemberTest_Failure Method");
////			when(authService.removeOrgMember(Mockito.<HttpServletRequest>any(), Mockito.<AddMemberRequest>any()))
////					.thenThrow(Exception.class);
////			ResponseEntity<BaseResponse> response = userController.removeOrgMember(Mockito.<HttpServletRequest>any(),
////					Mockito.<AddMemberRequest>any());
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////			assertEquals("Exception Occured while removing organization member!", response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::removeOrgMemberTest_Failure : Unknown error {} ", e.getMessage(),
////					e);
////		}
////	}
////
////	@Test
////	public void addOrgMemberTest_Sucsess() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::addOrgMemberTest_Sucsess Method");
////			when(authService.addOrgMember(request, getAddMemberRequest())).thenReturn(getBaseResponse());
////			ResponseEntity<BaseResponse> response = userController.addOrgMember(request, getAddMemberRequest());
////			assertEquals(HttpStatus.OK, response.getStatusCode());
////			assertEquals(getBaseResponse(), response.getBody());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::addOrgMemberTest_Sucsess : Unknown error {} ", e.getMessage(), e);
////		}
////	}
////
////	@Test
////	public void addOrgMemberTest_Failure() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::addOrgMemberTest_Failure Method");
////			when(authService.addOrgMember(Mockito.<HttpServletRequest>any(), Mockito.<AddMemberRequest>any()))
////					.thenThrow(Exception.class);
////			ResponseEntity<BaseResponse> response = userController.addOrgMember(Mockito.<HttpServletRequest>any(),
////					Mockito.<AddMemberRequest>any());
////			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
////			assertEquals("Exception Occured while adding organization member!", response.getBody().getMessage());
////			assertEquals(false, response.getBody().getSuccess());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::addOrgMemberTest_Failure : Unknown error {} ", e.getMessage(), e);
////		}
////	}
//
//	@Test
//	public void getUserDetailsObjectTest_Sucsess1() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::getUserDetailsObjectTest_Sucsess1 Method");
//			when(authService.loadUserByUsername(USERNAME)).thenReturn(getUserDetails());
//			ResponseEntity<BaseResponse> response = userController.getUserDetailsObject(USERNAME);
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//			assertEquals(getUserDetails(), response.getBody().getPayload());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::getUserDetailsObjectTest_Sucsess1 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getUserDetailsObjectTest_Failure1() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::getUserDetailsObjectTest_Failure1 Method");
//			when(authService.loadUserByUsername(Mockito.anyString())).thenReturn(getUserDetails());
//			ResponseEntity<BaseResponse> response = userController.getUserDetailsObject(null);
//			assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
//			assertEquals(null, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::getUserDetailsObjectTest_Failure1 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getUserDetailsObjectTest_Failure2() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::getUserDetailsObjectTest_Failure2 Method");
//			when(authService.loadUserByUsername(Mockito.anyString())).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController.getUserDetailsObject(USERNAME);
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//			assertEquals(null, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::getUserDetailsObjectTest_Failure2 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveUserTest_Success() {
//
//		try {
//			LOGGER.debug("Inside LoginControllerTest::saveUserTest_Success Method");
//			when(userService.save(Mockito.<RegistrationUser>any(), Mockito.<HttpServletRequest>any()))
//					.thenReturn(getBaseResponse());
//			ResponseEntity<BaseResponse> response = userController.saveUser(Mockito.<RegistrationUser>any(),
//					Mockito.<HttpServletRequest>any());
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::saveUserTest_Success method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void saveUserTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::saveUserTest_Failure Method");
//			when(userService.save(Mockito.<RegistrationUser>any(), Mockito.<HttpServletRequest>any()))
//					.thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController.saveUser(Mockito.<RegistrationUser>any(),
//					Mockito.<HttpServletRequest>any());
//			;
//			assertEquals("Exception Occured while saving user!", response.getBody().getMessage());
//
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::saveUserTest_Failure method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	// Testcase for update and save mfa for that user
//
//	@Test
//	public void generateMfaQrAndSecretTest_Success() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::generateMfaQrAndSecretTest_Success Method");
//			BaseResponse baseResponse = getBaseResponse();
//			baseResponse.setSuccess(null);
//			;
//			when(userService.generateMfaQrAndSecret(Mockito.<RegistrationUser>any())).thenReturn(baseResponse);
//			ResponseEntity<BaseResponse> response = userController
//					.generateMfaQrAndSecret(Mockito.<RegistrationUser>any());
//			assertEquals(null, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::generateMfaQrAndSecretTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void generateMfaQrAndSecretTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::generateMfaQrAndSecretTest_Failure Method");
//			when(userService.generateMfaQrAndSecret(Mockito.<RegistrationUser>any())).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController
//					.generateMfaQrAndSecret(Mockito.<RegistrationUser>any());
//			assertEquals("Exception Occured while generating MFA QR and Secret!", response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::generateMfaQrAndSecretTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	// TestCase for responsible to verify user email
//
//	@Test
//	public void verifyUserTest_Success() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::verifyUserTest_Success Method");
//			when(authService.verify(Mockito.<AuthRequest>any()));
//			BaseResponse response = userController.verifyUser(Mockito.anyString());
//			assertEquals(true, response.getSuccess());
//			assertEquals("User verified.", response.getMessage());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::verifyUserTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void verifyUserTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::verifyUserTest_Failure Method");
//			when(authService.verify(Mockito.<AuthRequest>any())).thenThrow(Exception.class);
//			BaseResponse response = userController.verifyUser(Mockito.anyString());
//			assertEquals("Failed to verify user.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::verifyUserTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	// TestCase --> responsible for resend verification link
//
//	@Test
//	public void resendVerificationEmailTest_Success() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::resendVerificationEmailTest_Success Method");
//			when(userService.resendVerificationLink(Mockito.<HttpServletRequest>any(),Mockito.anyString())).thenReturn(getBaseResponse());
//			ResponseEntity<BaseResponse> response = userController.resendVerificationEmail(Mockito.anyString(), Mockito.<HttpServletRequest>any());
//			assertEquals(true, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::resendVerificationEmailTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void resendVerificationEmailTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::resendVerificationEmailTest_Failure Method");
//			when(userService.resendVerificationLink(Mockito.<HttpServletRequest>any(),Mockito.anyString())).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController.resendVerificationEmail(Mockito.anyString(), Mockito.<HttpServletRequest>any());
//			assertEquals(true, response.getBody().getSuccess());
//
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::resendVerificationEmailTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	// Test Case --> responsible for to request for account approval to approve user
//
//	@Test
//	public void requestForAccountApprovalTest_Success() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::requestForAccountApprovalTest_Success Method");
//			when(userService.requestForAccountApproval(Mockito.<HttpServletRequest>any(),Mockito.anyString()))
//					.thenReturn(getBaseResponse());
//			ResponseEntity<BaseResponse> response = userController.requestForAccountApproval(Mockito.anyString(),
//					Mockito.<HttpServletRequest>any());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::requestForAccountApprovalTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void requestForAccountApprovalTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::requestForAccountApprovalTest_Failure Method");
//			when(userService.requestForAccountApproval(Mockito.<HttpServletRequest>any(), Mockito.anyString()))
//					.thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController.requestForAccountApproval(Mockito.anyString(),
//					Mockito.<HttpServletRequest>any());
//			assertEquals(true, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::requestForAccountApprovalTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	// TestCase --> responsible for to approve user
//
//	@Test
//	public void approveUserTest_Success() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::approveUserTest_Success Method");
//			when(userService.approve(Mockito.anyString(), Mockito.<Boolean>any(), Mockito.<RegistrationUser>any()));
//			BaseResponse response = userController.approveUser(Mockito.anyString(), Mockito.<Boolean>any(), Mockito.<RegistrationUser>any() );
//
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::approveUserTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	// TestCase for to register a user via Google
//
//	@Test
//	public void registerForGoogleTest_Success() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::registerForGoogleTest_Success Method");
//			when(userService.registerForGoogleLogin(Mockito.<RegistrationUser>any())).thenReturn(getBaseResponse());
//			ResponseEntity<BaseResponse> response = userController.registerForGoogle(Mockito.<RegistrationUser>any());
////			assertEquals(true, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::registerForGoogleTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void registerForGoogleTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::registerForGoogleTest_Failure Method");
//			when(userService.registerForGoogleLogin(Mockito.<RegistrationUser>any())).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController.registerForGoogle(Mockito.<RegistrationUser>any());
//			assertEquals(false, response.getBody().getSuccess());
//			assertEquals("Exception Occured while registering/logging in via Google!", response.getBody().getMessage());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::registerForGoogleTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	// TestCase for to save a new pass-code
//
//	@Test
//	public void addPasscodeTest_Success() {
//		try {
//			ResetPasswordResponse resetPasswordResponse = new ResetPasswordResponse();
//			LOGGER.debug("Inside LoginControllerTest::addPasscodeTest_Success Method");
//			when(userService.addPasscode(Mockito.anyString(), Mockito.anyString())).thenReturn(getBaseResponse());
//			ResponseEntity<BaseResponse> response = userController.addPasscode(MAILID, resetPasswordResponse);
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::addPasscodeTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void addPasscodeTest_Failure() {
//		try {
//			ResetPasswordResponse rpr = new ResetPasswordResponse();
//			LOGGER.debug("Inside LoginControllerTest::addPasscodeTest_Failure Method");
//			when(userService.addPasscode(Mockito.anyString(), Mockito.anyString())).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController.addPasscode(MAILID, rpr);
//			assertEquals(null, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::addPasscodeTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	// TestCase for to validate existing pass-code
//
//	@Test
//	public void checkPasscodeTest_Success() {
//		try {
//			BaseResponse baseResponse = getBaseResponse();
//			baseResponse.setStatusCode("200");
//			LOGGER.debug("Inside LoginControllerTest::checkPasscodeTest_Success Method");
//			when(userService.checkPasscode(Mockito.anyString(), Mockito.anyString())).thenReturn(baseResponse);
//			ResponseEntity<BaseResponse> response = userController.checkPasscode(Mockito.anyString(),
//					Mockito.anyString());
//			assertEquals("200", response.getBody().getStatusCode());
//			assertEquals(true, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::checkPasscodeTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkPasscodeTest_Failure() {
//		try {
//
//			LOGGER.debug("Inside LoginControllerTest::checkPasscodeTest_Failure Method");
//			BaseResponse baseResponse = new BaseResponse();
//			when(userService.checkPasscode(Mockito.anyString(), Mockito.anyString())).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController.checkPasscode(Mockito.anyString(),
//					Mockito.anyString());
//			assertEquals(baseResponse, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::checkPasscodeTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	// TestCase for to save new password
//	@Test
//	public void saveNewPasswordTest_Success() {
//		try {
//
//			LOGGER.debug("Inside LoginControllerTest::saveNewPasswordTest_Success Method");
//			when(userService.savePassword(Mockito.<ChangePasswordRequest>any())).thenReturn(getBaseResponse());
//			ResponseEntity<BaseResponse> response = userController.setPassword(Mockito.<ChangePasswordRequest>any());
////			assertEquals(true, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::saveNewPasswordTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveNewPasswordTest_Failure() {
//		try {
//
//			LOGGER.debug("Inside LoginControllerTest::saveNewPasswordTest_Failure Method");
//			when(userService.savePassword(Mockito.<ChangePasswordRequest>any())).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController.setPassword(Mockito.<ChangePasswordRequest>any());
//			assertEquals(false, response.getBody().getSuccess());
//			assertEquals("Exception Occured while saving password!", response.getBody().getMessage());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::saveNewPasswordTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	// TestCase for validate an existing user
//	@Test
//	public void validateUserForGLoginTest_Success() {
//		try {
//
//			LOGGER.debug("Inside LoginControllerTest::validateUserForGLoginTest_Success Method");
//			when(userService.validateUserForGLogin(Mockito.anyString())).thenReturn(getBaseResponse());
//			BaseResponse response = userController.validateUserForGLogin(Mockito.anyString());
////			assertEquals(true, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::validateUserForGLoginTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateUserForGLoginTest_Failure() {
//		try {
//
//			LOGGER.debug("Inside LoginControllerTest::validateUserForGLoginTest_Failure Method");
//			when(userService.validateUserForGLogin(Mockito.anyString())).thenThrow(Exception.class);
//			BaseResponse response = userController.validateUserForGLogin(Mockito.anyString());
//			assertEquals(false, response.getSuccess());
//			assertEquals("Exception Occured while validating user!", response.getMessage());
//
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::validateUserForGLoginTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	// TestCase to update an existing user
//
//	@Test
//	public void updateUserTest_Success() {
//
//		try {
//			BaseResponse baseResponse = new BaseResponse();
//			LOGGER.debug("Inside LoginControllerTest::updateUserTest_Success Method");
//			when(userService.updateUser(Mockito.<HttpServletRequest>any(), Mockito.<RegistrationUser>any()))
//					.thenReturn(baseResponse);
//			baseResponse.setStatusCode("401");
//			ResponseEntity<BaseResponse> response = userController.updateUser(Mockito.<RegistrationUser>any(),
//					Mockito.<HttpServletRequest>any());
//			assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::updateUserTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void updateUserTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::updateUserTest_Failure Method");
//			when(userService.updateUser(Mockito.<HttpServletRequest>any(), Mockito.<RegistrationUser>any()))
//					.thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController.updateUser(Mockito.<RegistrationUser>any(),
//					Mockito.<HttpServletRequest>any());
//			assertEquals(false, response.getBody().getSuccess());
//
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::updateTest_Failure method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void updateUserTest_anotherSuccess() {
//
//		try {
//			LOGGER.debug("Inside LoginControllerTest::updateUserTest_Success Method");
//			when(userService.updateUser(Mockito.<HttpServletRequest>any(), Mockito.<RegistrationUser>any()))
//					.thenReturn(getBaseResponse());
//			ResponseEntity<BaseResponse> response = userController.updateUser(Mockito.<RegistrationUser>any(),
//					Mockito.<HttpServletRequest>any());
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::updateUserTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	// TestCase to fetch user profile details
//
//	@Test
//	public void getUserTest_Success() {
//
//		try {
//			LOGGER.debug("Inside LoginControllerTest::getUserTest_Success Method");
//			when(userService.getUser(Mockito.<HttpServletRequest>any(), Mockito.<AuthRequest>any())).thenReturn(getBaseResponse());
//			ResponseEntity<BaseResponse> response = userController.getUser(Mockito.<HttpServletRequest>any(), Mockito.<AuthRequest>any());
//			assertEquals(true, response.getBody().getSuccess());
//			assertEquals("Profile Details fetched.", response.getBody().getMessage());
//			assertEquals(getRegistrationUser(), response.getBody().getPayload());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::getUserTest_Success method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void getUserTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::getUserTest_Failure Method");
//			when(userService.getUser(Mockito.<HttpServletRequest>any(), Mockito.<AuthRequest>any())).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController.getUser(Mockito.<HttpServletRequest>any(), Mockito.<AuthRequest>any());
//			assertEquals(false, response.getBody().getSuccess());
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//			assertEquals("Exception Occured while fetching user profile details!", response.getBody().getMessage());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::getUserTest_Failure method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	// TestCase to delete an existing user
//
//	@Test
//	public void deleteUserTest_Success() {
//
//		try {
//			LOGGER.debug("Inside LoginControllerTest::deleteUserTest_Success Method");
//			when(userService.deleteUser(Mockito.anyString())).thenReturn(getBaseResponse());
//			ResponseEntity<BaseResponse> response = userController.deleteUser(Mockito.anyString());
////			assertEquals(true, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::deleteUserTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void deleteUserTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::deleteUserTest_Failure Method");
//			when(userService.deleteUser(Mockito.anyString())).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController.deleteUser(Mockito.anyString());
//			assertEquals(false, response.getBody().getSuccess());
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//			assertEquals("Exception Occured while deleting user!", response.getBody().getMessage());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::deleteUserTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	// TestCase to update mfa for that user
//
//	@Test
//	public void getQrFor2FATest_Success() {
//
//		try {
//			LOGGER.debug("Inside LoginControllerTest::getQrFor2FATest_Success Method");
//			when(userService.updateUser2FA(Mockito.<HttpServletRequest>any())).thenReturn(getBaseResponse());
//			BaseResponse response = userController.getQrFor2FA(Mockito.<HttpServletRequest>any());
////			assertEquals(true, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::getQrFor2FATest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	// TestCase to to get User Details
//
//	@Test
//	public void getUsrTest_Success() {
//
//		try {
//			LOGGER.debug("Inside LoginControllerTest::getUserTest_Success Method");
//			when(helperUtil.loadDaoUserByMailId((Mockito.anyString()))).thenReturn(getDaoUser());
//			ResponseEntity<UserProfile> response = userController.getUserByEmail(Mockito.anyString());
//			assertEquals(200, response.getStatusCodeValue());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::getUserTest_Success method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void getUsrTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::getUserTest_Failure Method");
//			when(helperUtil.loadDaoUserByMailId((Mockito.anyString()))).thenThrow(Exception.class);
//			ResponseEntity<UserProfile> response = userController.getUserByEmail(Mockito.anyString());
//			assertEquals(null, response.getBody());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::getUserTest_Failure method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	// TestCase to to get User Details
//
//	@Test
//	public void verifyUsernameTest_Success() {
//
//		try {
//			LOGGER.debug("Inside LoginControllerTest::verifyUsernameTest_Success Method");
//			ResponseEntity<Boolean> response = userController.verifyUsername(Mockito.anyString());
//			helperUtil.isValidUsername(USERNAME);
//			helperUtil.isValidEmail(MAILID);
//			helperUtil.checkForDuplicateUsername("test");
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::verifyUsernameTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void verifyUsernameTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::verifyUsernameTest_Failure Method");
//			when(helperUtil.isValidUsername(Mockito.anyString())).thenThrow(Exception.class);
//			ResponseEntity<Boolean> response = userController.verifyUsername(Mockito.anyString());
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::verifyUsernameTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void verifyEmailTest_Success() {
//
//		try {
//			LOGGER.debug("Inside LoginControllerTest::verifyEmailTest_Success Method");
//			ResponseEntity<Boolean> response = userController.verifyEmail(Mockito.anyString());
//			helperUtil.isValidEmail(MAILID);
//			helperUtil.checkForDuplicateEmail("test@gmail.com");
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::verifyEmailTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void verifyEmailTest_Failure() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::verifyEmailTest_Failure Method");
//			when(helperUtil.isValidUsername(Mockito.anyString())).thenThrow(Exception.class);
//			ResponseEntity<Boolean> response = userController.verifyUsername(Mockito.anyString());
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::verifyEmailTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void verifyUserAcces_Success() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::verifyEmailTest_Success Method");
//			when(userService.verifyUserAccess(Mockito.<HttpServletRequest>any(), Mockito.anyString())).thenReturn(true);
//			;
//			ResponseEntity<Boolean> response = userController.verifyUserAccess(Mockito.<HttpServletRequest>any(),
//					Mockito.anyString());
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::verifyEmailTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
////	@Test
////	public void getOrganizationDetailsTest_Success() {
////
////		try {
////			LOGGER.debug("Inside LoginControllerTest::getOrganizationDetailsTest_Success Method");
////			when(authService.getOrganizationDetails(Mockito.<HttpServletRequest>any())).thenReturn(getBaseResponse());
////			ResponseEntity<BaseResponse> response = userController
////					.getOrganizationDetails(Mockito.<HttpServletRequest>any());
////			assertEquals(org.springframework.http.HttpStatus.OK, response.getStatusCode());
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::getOrganizationDetailsTest_Success method : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
//
////	@Test
////	public void getOrganizationDetailsTest_Failure() {
////		try {
////			LOGGER.debug("Inside LoginControllerTest::getOrganizationDetailsTest_Failure Method");
////			when(authService.getOrganizationDetails(Mockito.<HttpServletRequest>any())).thenThrow(Exception.class);
////			ResponseEntity<BaseResponse> response = userController
////					.getOrganizationDetails(Mockito.<HttpServletRequest>any());
////			assertEquals("Exception Occured while fetching organization details!", response.getBody().getMessage());
////
////		} catch (Exception e) {
////			LOGGER.error("Inside LoginControllerTest::getOrganizationDetailsTest_Failure method : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
//
//	@Test
//	public void checkPasswordTest_Sucsess() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::checkPasswordTest_Sucsess Method");
//			BaseResponse baseResponse = getBaseResponse();
//			PasswordCheckRequest passwordCheckRequest = getPasswordCheckRequest();
//			baseResponse.setMessage("Passwords Matched");
//			when(userService.checkPassword(request, PASSWORD)).thenReturn(baseResponse);
//			ResponseEntity<BaseResponse> response = userController.checkPassword(request, passwordCheckRequest);
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//			assertEquals("Passwords Matched", response.getBody().getMessage());
//			assertEquals(true, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::checkPasswordTest_Sucsess : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkPasswordTest_Failure1() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::checkPasswordTest_Failure1 Method");
//			BaseResponse baseResponse = getBaseResponse();
//			PasswordCheckRequest passwordCheckRequest = getPasswordCheckRequest();
//			baseResponse.setSuccess(false);
//			baseResponse.setMessage("Passwords don't match");
//			when(userService.checkPassword(request, PASSWORD)).thenReturn(baseResponse);
//			ResponseEntity<BaseResponse> response = userController.checkPassword(request, passwordCheckRequest);
//			assertEquals(HttpStatus.OK, response.getStatusCode());
//			assertEquals("Passwords don't match", response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::checkPasswordTest_Failure1 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkPasswordTest_Failure2() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::checkPasswordTest_Failure2 Method");
//			BaseResponse baseResponse = getBaseResponse();
//			PasswordCheckRequest passwordCheckRequest = getPasswordCheckRequest();
//			baseResponse.setSuccess(false);
//			baseResponse.setMessage("Exception Occured while comparing password!");
//			when(userService.checkPassword(request, PASSWORD)).thenThrow(Exception.class);
//			ResponseEntity<BaseResponse> response = userController.checkPassword(request, passwordCheckRequest);
//			assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//			assertEquals("Exception Occured while comparing password!", response.getBody().getMessage());
//			assertEquals(false, response.getBody().getSuccess());
//
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::checkPasswordTest_Failure2 : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public  void fetchUsernameFromTokenTest() {
//		try {
//			LOGGER.debug("Inside UserControllerTest::fetchUsernameFromTokenTest");
//			BaseResponse baseResponse = userService.fetchUserNameFromToken(request);
//			assertEquals(String.valueOf(HttpStatus.OK.value()), baseResponse.getStatusCode());
//		} catch (Exception e) {
//			LOGGER.error("Inside UserControllerTest::fetchUsernameFromTokenTest : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void fetchUserProfileFromUsernameTest() {
//		try {
//			LOGGER.debug("Inside UserControllerTest::fetchUserProfileFromUsernameTest");
//			UserProfile userProfile = userRepo.findByUsername("harini");
//			assertEquals(String.valueOf("harini"), userProfile.getUsername());
//		} catch (Exception e) {
//			LOGGER.error("Inside UserControllerTest::fetchUsernameFromTokenTest : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//}
