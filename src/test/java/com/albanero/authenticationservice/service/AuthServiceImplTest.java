package com.albanero.authenticationservice.service;//package com.albanero.authenticationservice.service;
//
//import static org.junit.Assert.assertEquals;
//import static org.mockito.Mockito.doNothing;
//import static org.mockito.Mockito.when;
//
//import java.io.UnsupportedEncodingException;
//import java.net.URI;
//import java.text.SimpleDateFormat;
//import java.util.ArrayList;
//import java.util.Date;
//import java.util.List;
//import java.util.Optional;
//import java.util.Properties;
//
//import jakarta.mail.Message;
//import jakarta.mail.MessagingException;
//import jakarta.mail.Session;
//import jakarta.mail.Transport;
//import jakarta.mail.internet.AddressException;
//import jakarta.mail.internet.InternetAddress;
//import jakarta.mail.internet.MimeMessage;
//import jakarta.servlet.http.HttpServletRequest;
//
//import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
//import org.jasypt.util.text.BasicTextEncryptor;
//import org.junit.Before;
//import org.junit.Test;
//import org.junit.runner.RunWith;
//import org.mockito.ArgumentMatchers;
//import org.mockito.InjectMocks;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.mockito.MockitoAnnotations;
//import org.powermock.api.mockito.PowerMockito;
//import org.powermock.core.classloader.annotations.PowerMockIgnore;
//import org.powermock.core.classloader.annotations.PrepareForTest;
//import org.powermock.modules.junit4.PowerMockRunner;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.cloud.client.ServiceInstance;
//import org.springframework.cloud.client.discovery.DiscoveryClient;
//import org.springframework.http.HttpEntity;
//import org.springframework.http.HttpMethod;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
//import org.springframework.mail.javamail.JavaMailSender;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.test.util.ReflectionTestUtils;
//import org.springframework.util.StringUtils;
//import org.springframework.web.client.RestTemplate;
//
//import com.albanero.authservice.common.dto.request.AddMemberRequest;
//import com.albanero.authservice.common.dto.request.AuthRequest;
//import com.albanero.authservice.common.dto.request.ChangePasswordRequest;
//import com.albanero.authservice.common.dto.request.OrgLevelDetails;
//import com.albanero.authservice.common.dto.request.RegistrationUser;
//import com.albanero.authservice.common.dto.request.SecurityQuesRequest;
//import com.albanero.authservice.common.dto.request.UserIdDetails;
//import com.albanero.authservice.common.dto.response.AuthResponse;
//import com.albanero.authservice.common.dto.response.AuthTokenResponse;
//import com.albanero.authservice.common.dto.response.BaseResponse;
//import com.albanero.authservice.common.dto.response.FetchResponse;
//import com.albanero.authservice.common.dto.response.ProductRoles;
//import com.albanero.authservice.common.dto.response.RegisterUserResponse;
//import com.albanero.authservice.common.dto.response.RiskResponse;
//import com.albanero.authservice.common.util.RestUtil;
//import com.albanero.authservice.common.util.WebClientUtil;
//import com.albanero.authservice.model.DaoUser;
//import com.albanero.authservice.model.GoogleAuthDetails;
//import com.albanero.authservice.model.Organization;
//import com.albanero.authservice.model.Product;
//import com.albanero.authservice.model.ProductRoleDetails;
//import com.albanero.authservice.model.SecurityQuestionDetails;
//import com.albanero.authservice.model.SecurityQuestions;
//import com.albanero.authservice.model.UserOrgRole;
//import com.albanero.authservice.model.UserRoleDetails;
//import com.albanero.authservice.model.UserTokenDetails;
//import com.albanero.authservice.repository.OrgRepository;
//import com.albanero.authservice.repository.ProductRepository;
//import com.albanero.authservice.repository.SecurityQuestionsRepo;
//import com.albanero.authservice.repository.UserOrgRoleRepository;
//import com.albanero.authservice.repository.UserRepository;
//import com.albanero.authservice.service.UserRoleService;
//import com.albanero.authservice.service.impl.AuthServiceImpl;
//
//@RunWith(PowerMockRunner.class)
//@PowerMockIgnore({ "jakarta.management.*", "jakarta.xml.*", "org.xml.sax.*", "org.w3c.dom.*",
//	"org.springframework.context.*", "org.apache.log4j.*", "org.apache.commons.logging.*", "org.jacoco.*",
//	"jdk.internal.reflect.*", "jakarta.crypto.*" })
//@PrepareForTest({ RestUtil.class, StringUtils.class, StandardPBEStringEncryptor.class, BasicTextEncryptor.class,
//	jakarta.mail.Session.class })
//public class AuthServiceImplTest {
//
//	private static final Logger LOGGER = LoggerFactory.getLogger(AuthServiceImplTest.class);
//	private static final String ACCESS_TOKEN = "token.token.token";
//	private static final String REFRESH_TOKEN = "refreshtoken";
//	private static final String HASHED_TOKEN = "hashedtoken";
//	private static final String VALID_BEARER_TOKEN = "Bearer refresh.token";
//	private static final String INVALID_BEARER_TOKEN = "Bearer refreshtoken";
//	private static final String ENCRYPTED_RT = "kSvwg63H+yTbF2V+FvrDUxq26xCbPZzA2aB+vgGcj5QEnkpTNILJ5wGiT6/CAL/O";
//	private static final String ENCRYPTED_VALID_BEARER_TOKEN = "Bearer OITRUroPIr8qCxg/efrV8iLG0VXOuiE2";
//	private static final String ENCRYPTED_BEARER_TOKEN = "Bearer kroTAT5RWQTTsbjNSWrVoP2VuPbD6j9Z";
//	private static final String VALID_USERNAME = "username";
//	private static final String INVALID_USERNAME = "user#name";
//	private static final String BLANK_USERNAME = " ";
//	private static final String INVALID_PASSWORD = "test_password";
//	private static final String VALID_PASSWORD = "112Test@password";
//	public static final Long USER_VERIFICATION_TOKEN_DURATION = 3 * 24 * 60 * 60000l;
//	private static final String VALID_MAILID = "mail@gmail.com";
//	private static final String INVALID_MAILID = "mailgmail.com";
//	private static final String FIRST_NAME = "First";
//	private static final String LAST_NAME = "Last";
//	private static final String SECRET = "secret";
//	private static final String ID = "id";
//	private static final String RISK_LEVEL = "low";
//	private static final String SECURITY_QUESTION = "security_question";
//	private static final String SECURITY_ANSWER = "security_answer";
//	private static final Boolean IS_USING_2FA = true;
//	private URI uri = URI.create("http://www.test.com/");
//	private List<String> list = new ArrayList();
//	private static final String ORG_NAME = "org_name";
//	private static final Long OTP_TOKEN_DURATION = 300000L;
//	private static final String CODE = "code";
//	private static final String HASHED_RT = "token";
//	private static final String PASSCODE = "passcode";
//	private static final String HASHED_PASS = "$2a$04$rdrEZNUrsrVuPSJ3tjI28O9QK1CV7wHdS9qVu0w7MF.X.CSqvm8/S";
//	private static final String NEW_PASSWORD = "1nero#@albaS$";
//	private static final String TOKEN = "token";
//	private static final String OTP_TOKEN = "8vdh3dCQ0yPcZz3WqO2mV4alUUNaeldv";
//	private static final String VERIFICATION = "verify";
//	private static final String RIGHT_PASSWORD = "1albanero@#S$";
//	private static final String HASHED_ANSWER = "$2a$10$e9rjr4kX/9L540jr9TpJPO49TnGoFovTrTL1w3KGXNsJP0d0A0plC";
//
//	@Mock
//	private ServiceInstance serviceInstance;
//
//	@Mock
//	private static UserRepository userRepo;
//
//	@Mock
//	private static UserOrgRoleRepository userOrgRoleRepo;
//
//	@Mock
//	private static UserRoleService userRoleService;
//
//	@Mock
//	private OrgRepository orgRepo;
//
//	@Mock
//	private HttpServletRequest request;
//
//	@Mock
//	private DiscoveryClient discoveryClient;
//
//	@Mock
//	private RestTemplate restTemplate;
//
//	@Mock
//	private SecurityQuestionsRepo securityQuestionsRepo;
//
//	@Mock
//	private JavaMailSender mailSender;
//
//	@Mock
//	private MimeMessage mimeMessage;
//
//	@Mock
//	private Transport transport;
//
//	@Mock
//	private Session session;
//
//	@Mock
//	private PasswordEncoder bcryptEncoder;
//
//	@Mock
//	private RestUtil restUtil;
//
//	@Mock
//	private AuthenticationManager authenticationManager;
//
//	@Mock
//	private Authentication authentication;
//
//	@Mock
//	private ProductRepository productRepo;
//
//	@Mock
//	private UserTokenDetails userTokenDetails;
//
//	@Mock
//	private BasicTextEncryptor basicTextEncryptor;
//
//	@Mock
//	private WebClientUtil webClientUtil;
//
//	@InjectMocks
//	private AuthServiceImpl authService;
//
//	@Before
//	public void setUp() throws Exception {
//		MockitoAnnotations.initMocks(this);
//		List<ServiceInstance> serviceInstanceList = new ArrayList();
//		serviceInstanceList.add(serviceInstance);
//		when(discoveryClient.getInstances(Mockito.anyString())).thenReturn(serviceInstanceList);
//		when(serviceInstance.getUri()).thenReturn(uri);
//	}
//
//	private Organization getOrganization() {
//		Organization org = new Organization();
//		return org;
//	}
//
//	private Product getProduct() {
//		Product product = new Product();
//		product.setAdmin(list);
//		product.setMember(list);
//		return product;
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
//		authRequest.setPassword("");
//		return authRequest;
//	}
//
//	private AuthTokenResponse getAuthTokenResponse() {
//		AuthTokenResponse authTokenResponse = new AuthTokenResponse();
//		return authTokenResponse;
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
//	private UserTokenDetails getUserTokenDetails() {
//		UserTokenDetails userTokenDetails = new UserTokenDetails();
//		return userTokenDetails;
//	}
//
//	private DaoUser getDaoUser() {
//		DaoUser user = new DaoUser();
//		user.setId(ID);
//		user.setUsername(VALID_USERNAME);
//		user.setPassword(VALID_PASSWORD);
//		user.setRefreshToken(getUserTokenDetails());
//		user.setRole("ROLE_ADMIN");
//		user.setFirstName(FIRST_NAME);
//		user.setLastName(LAST_NAME);
//		return user;
//	}
//
//	private RegistrationUser getRegistrationUser() {
//		RegistrationUser registrationUser = new RegistrationUser();
//		return registrationUser;
//	}
//
//	private SecurityQuestions getSecurityQuestions() {
//		SecurityQuestions securityQuestions = new SecurityQuestions();
//		securityQuestions.setId(ID);
//		list.add(SECURITY_QUESTION);
//		securityQuestions.setQuestions(list);
//		return securityQuestions;
//	}
//
//	private SecurityQuestionDetails getSecurityQuestionDetails() {
//		SecurityQuestionDetails securityQuestionDetails = new SecurityQuestionDetails();
//		securityQuestionDetails.setQuestion(SECURITY_QUESTION);
//		securityQuestionDetails.setIsUsingSQ(true);
//		return securityQuestionDetails;
//	}
//
//	private SecurityQuesRequest getSecurityQuesRequest() {
//		SecurityQuesRequest secutiryQuesRequest = new SecurityQuesRequest();
//		secutiryQuesRequest.setIsUsingSQ(true);
//		secutiryQuesRequest.setQuestion(SECURITY_QUESTION);
//		secutiryQuesRequest.setAnswer(SECURITY_ANSWER);
//		return secutiryQuesRequest;
//	}
//
//	private GoogleAuthDetails getGoogleAuthDetails() {
//		GoogleAuthDetails googleAuthDetails = new GoogleAuthDetails();
//		googleAuthDetails.setIsUsing2FA(true);
//		return googleAuthDetails;
//	}
//
//	private UserRoleDetails getUserRoleDetails() {
//		UserRoleDetails userRoleDetails = new UserRoleDetails();
//		return userRoleDetails;
//	}
//
//	private ProductRoleDetails getProductRoleDetails() {
//		ProductRoleDetails productRoleDetails = new ProductRoleDetails();
//		productRoleDetails.setProductId(ID);
//		productRoleDetails.setRole("ADMIN");
//		return productRoleDetails;
//	}
//
//	//	private AddMemberRequest getAddMemberRequest() {
//	//		AddMemberRequest addMemberRequest = new AddMemberRequest();
//	//		addMemberRequest.setProdId(ID);
//	//		addMemberRequest.setRole("ADMIN");
//	//		addMemberRequest.setUsername(VALID_PASSWORD);
//	//		return addMemberRequest;
//	//	}
//
//	private ProductRoles getProductRoles() {
//		ProductRoles productRoles = new ProductRoles();
//		productRoles.setProductName(null);
//		productRoles.setProductRole("ADMIN");
//		return productRoles;
//	}
//
//	private FetchResponse getFetchResponse() {
//		FetchResponse fetchResponse = new FetchResponse();
//		return fetchResponse;
//	}
//
//	private RiskResponse getRiskResponse() {
//		RiskResponse riskResponse = new RiskResponse();
//		riskResponse.setRiskLevel(RISK_LEVEL);
//		return riskResponse;
//	}
//
//	private UserOrgRole getUserOrgRole() {
//		UserOrgRole userOrgRole = new UserOrgRole();
//		return userOrgRole;
//	}
//
//	private UserIdDetails getUserIdDetails() {
//		UserIdDetails userIdDetails = new UserIdDetails();
//		return userIdDetails;
//	}
//
//	public static Optional<DaoUser> daouser(String name) {
//		Optional<DaoUser> daoUser = userRepo.findById(name);
//		return daoUser;
//	}
//
//	@Test
//	public void resendVerificationLinkTest_Success() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::resendVerificationLinkTest_Success Method");
//			when(userRepo.findByMailId(Mockito.anyString())).thenReturn(null);
//			BaseResponse response = authService.resendVerificationLink(Mockito.anyString());
//			assertEquals("Given email is not a registered email address.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::resendVerificationLinkTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void resendVerificationLinkTest_Failure1() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::resendVerificationLinkTest_Failure1 Method");
//			when(userRepo.findByMailId(Mockito.anyString())).thenThrow(UnsupportedEncodingException.class);
//			BaseResponse response = authService.resendVerificationLink(Mockito.anyString());
//			assertEquals("Exception occured in sending verification email.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::resendVerificationLinkTest_Failure1 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void resendVerificationLinkTest_Failure2() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::resendVerificationLinkTest_Failure2 Method");
//			when(userRepo.findByMailId(Mockito.anyString())).thenThrow(UnsupportedEncodingException.class);
//			BaseResponse response = authService.resendVerificationLink(Mockito.anyString());
//			assertEquals("Exception occured in sending verification email.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::resendVerificationLinkTest_Failure2 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void requestForAccountApprovalTest_Failure3() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::requestForAccountApprovalTest_Failure Method");
//			when(userRepo.findByEmailVerificationCode(CODE)).thenThrow(UnsupportedEncodingException.class);
//			BaseResponse response = authService.requestForAccountApproval(CODE, Mockito.<HttpServletRequest>any());
//			assertEquals("Approval Email could not be sent", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::requestForAccountApprovalTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void requestForAccountApprovalTest_Failure4() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::requestForAccountApprovalTest_Failure Method");
//			when(userRepo.findByEmailVerificationCode(CODE)).thenThrow(MessagingException.class);
//			BaseResponse response = authService.requestForAccountApproval(CODE, Mockito.<HttpServletRequest>any());
//			assertEquals("Approval Email could not be sent", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::requestForAccountApprovalTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void approveTest_Success1() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::approveTest_Success Method");
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(null);
//			BaseResponse response = authService.approve(VALID_MAILID, Mockito.anyBoolean());
//			assertEquals("This user account does not exist.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::approveTest_Success method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void approveTest_Success2() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::approveTest_Success Method");
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(getDaoUser());
//			BaseResponse response = authService.approve(VALID_MAILID, Mockito.anyBoolean());
//			assertEquals("Account approval status has been changed.", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::approveTest_Success method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void approveTest_Failure1() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::approveTest_Failure Method");
//			when(userRepo.findByMailId(VALID_MAILID)).thenThrow(Exception.class);
//			BaseResponse response = authService.approve(VALID_MAILID, Mockito.anyBoolean());
//			assertEquals("Exception occured in changing account approval status.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::approveTest_Failure method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void generateMfaQrAndSecretTest_Success1() {
//		try {
//			RegistrationUser registrationUser = new RegistrationUser();
//			LOGGER.debug("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Success Method");
//			registrationUser.setUsername(INVALID_USERNAME);
//			registrationUser.setPassword(VALID_PASSWORD);
//			BaseResponse response = authService.generateMfaQrAndSecret(registrationUser);
//			assertEquals("Given username is not valid!", response.getMessage());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void generateMfaQrAndSecretTest_Success2() {
//		try {
//			RegistrationUser registrationUser = new RegistrationUser();
//			LOGGER.debug("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Success Method");
//			registrationUser.setUsername(VALID_MAILID);
//			BaseResponse response = authService.generateMfaQrAndSecret(registrationUser);
//			assertEquals("You cannot use a different email as username!", response.getMessage());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void generateMfaQrAndSecretTest_Success3() {
//		try {
//			RegistrationUser registrationUser = new RegistrationUser();
//			LOGGER.debug("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Success Method");
//			registrationUser.setUsername(VALID_USERNAME);
//			registrationUser.setPassword(INVALID_PASSWORD);
//			BaseResponse response = authService.generateMfaQrAndSecret(registrationUser);
//			assertEquals("Given user password is not valid!", response.getMessage());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void generateMfaQrAndSecretTest_Success4() {
//		try {
//			RegistrationUser registrationUser = new RegistrationUser();
//			LOGGER.debug("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Success Method");
//			registrationUser.setUsername(VALID_USERNAME);
//			registrationUser.setPassword(VALID_PASSWORD);
//			registrationUser.setConfirmedPassword(INVALID_PASSWORD);
//			BaseResponse response = authService.generateMfaQrAndSecret(registrationUser);
//			assertEquals("Password fields do not match!", response.getMessage());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void generateMfaQrAndSecretTest_Success5() {
//		try {
//			RegistrationUser registrationUser = new RegistrationUser();
//			LOGGER.debug("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Success Method");
//			registrationUser.setUsername(VALID_USERNAME);
//			registrationUser.setMailId(INVALID_MAILID);
//			registrationUser.setPassword(VALID_PASSWORD);
//			registrationUser.setConfirmedPassword(VALID_PASSWORD);
//			BaseResponse response = authService.generateMfaQrAndSecret(registrationUser);
//			assertEquals("Given user email is not valid!", response.getMessage());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void generateMfaQrAndSecretTest_Success6() {
//		try {
//
//			RegistrationUser registrationUser = new RegistrationUser();
//			LOGGER.debug("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Success Method");
//			registrationUser.setUsername(VALID_USERNAME);
//			registrationUser.setMailId(VALID_MAILID);
//			registrationUser.setPassword(VALID_PASSWORD);
//			registrationUser.setConfirmedPassword(VALID_PASSWORD);
//			when(userRepo.findByMailId(Mockito.anyString())).thenReturn(getDaoUser());
//			BaseResponse response = authService.generateMfaQrAndSecret(registrationUser);
//			assertEquals("A user already exists with the given identities!", response.getMessage());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void generateMfaQrAndSecretTest_Success7() {
//		try {
//
//			RegistrationUser registrationUser = new RegistrationUser();
//			RegisterUserResponse registerUserResponse = new RegisterUserResponse();
//			GoogleAuthDetails gad = new GoogleAuthDetails();
//
//			LOGGER.debug("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Success7 Method");
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(getDaoUser());
//			registrationUser.setUsername(VALID_USERNAME);
//			registrationUser.setPassword(VALID_PASSWORD);
//			registrationUser.setConfirmedPassword(VALID_PASSWORD);
//			registrationUser.setMailId(VALID_MAILID);
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(getDaoUser());
//
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			String secret = responseEntity.getBody();
//			gad.setSecret(secret);
//			gad.setIsUsing2FA(true);
//			registerUserResponse.setSecret(secret);
//			BaseResponse response = authService.generateMfaQrAndSecret(registrationUser);
//			assertEquals("QR image and MFA secret returned!", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void generateMfaQrAndSecretTest_Failure1() {
//		try {
//			restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
//			RegistrationUser registrationUser = new RegistrationUser();
//			RegisterUserResponse registerUserResponse = new RegisterUserResponse();
//			GoogleAuthDetails gad = new GoogleAuthDetails();
//
//			LOGGER.debug("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Failure7 Method");
//			registrationUser.setUsername(VALID_USERNAME);
//			registrationUser.setMailId(VALID_MAILID);
//			registrationUser.setPassword(VALID_PASSWORD);
//			registrationUser.setConfirmedPassword(VALID_PASSWORD);
//			when(userRepo.findByUsername(Mockito.anyString())).thenThrow(UnsupportedEncodingException.class);
//
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(Mockito.<ResponseEntity<String>>any());
//			String secret = responseEntity.getBody();
//			gad.setSecret("anything");
//			gad.setIsUsing2FA(false);
//			registerUserResponse.setSecret(secret);
//			BaseResponse response = authService.generateMfaQrAndSecret(registrationUser);
//			assertEquals("Exception occured in generating QR and Secret.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::generateMfaQrAndSecretTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void deleteUser_Success1() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::deleteUserTest_Success Method");
//			BaseResponse response = authService.deleteUser(null);
//			assertEquals("The given ID is either empty or null!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::deleteUserTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void deleteUser_Success2() {
//		try {
//			Optional<DaoUser> users = null;
//			LOGGER.debug("Inside AuthServiceImplTest::deleteUserTest_Success1 Method");
//			when(userRepo.findById(ID)).thenReturn(users);
//			BaseResponse response = authService.deleteUser(ID);
//			assertEquals("The given ID is incorrect!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::deleteUserTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void deleteUser_Success3() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::deleteUserTest_Success2 Method");
//			DaoUser optionalUser = new DaoUser();
//			when(userRepo.findById(ID)).thenReturn(Optional.of(optionalUser));
//			BaseResponse response = authService.deleteUser(ID);
//			System.out.println(response.getMessage());
//			assertEquals("User with ID : " + ID + " has been deleted!", response.getMessage());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::deleteUserTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getDecodedRefreshToken_Success1() {
//		try {
//			DaoUser user = new DaoUser();
//			userTokenDetails.setHashedRT(HASHED_RT);
//			LOGGER.debug("Inside AuthServiceImplTest::getDecodedRefreshToken_Success1 Method");
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			when(userRepo.findByHashedRT(HASHED_RT)).thenReturn(user);
//			StandardPBEStringEncryptor decryptor = new StandardPBEStringEncryptor();
//			decryptor.setPassword("Done");
//			String encryptedText = decryptor.encrypt(ENCRYPTED_RT);
//			user.setRefreshToken(userTokenDetails);
//			userTokenDetails.setEncryptedRT(encryptedText);
//			when(userTokenDetails.getEncryptedRT()).thenReturn(encryptedText);
//			String decryptedText = decryptor.decrypt(encryptedText);
//			when(basicTextEncryptor.decrypt(encryptedText)).thenReturn(decryptedText);
//
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::getDecodedRefreshTokenTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	//
//
//	@Test
//	public void getDecodedRefreshToken_Failure1() {
//		try {
//			DaoUser user = new DaoUser(); // userTokenDetails.setHashedRT(HASHED_RT); LOGGER.
//			LOGGER.debug("Inside AuthServiceImplTest::getDecodedRefreshToken_Failure Method");
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			when(userRepo.findByHashedRT(HASHED_RT)).thenReturn(user);
//			StandardPBEStringEncryptor decryptor = new StandardPBEStringEncryptor();
//			decryptor.setPassword("Done");
//			String encryptedText = decryptor.encrypt(ENCRYPTED_RT);
//			user.setRefreshToken(userTokenDetails);
//			userTokenDetails.setEncryptedRT(encryptedText);
//			String response = authService.getDecodedRefreshToken(HASHED_RT);
//			assertEquals(null, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::getDecodedRefreshTokenTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateUserForGLogin_Success1() {
//		try {
//			DaoUser user = new DaoUser();
//			LOGGER.debug("Inside AuthServiceImplTest::validateUserForGLogin_Success1 Method");
//			when(userRepo.findByMailId(VALID_USERNAME)).thenReturn(user);
//			BaseResponse response = authService.validateUserForGLogin(VALID_USERNAME);
//			assertEquals("User exists.", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::validateUserForGLoginTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateUserForGLogin_Failure1() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::validateUserForGLogin_Failure Method");
//			when(userRepo.findByMailId(Mockito.anyString())).thenReturn(null);
//			BaseResponse response = authService.validateUserForGLogin(Mockito.anyString());
//			assertEquals("User does not exist.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::validateUserForGLoginTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveRefreshToken_Success1() {
//		try {
//			DaoUser user = new DaoUser();
//			user.setUsername(VALID_USERNAME);
//			LOGGER.debug("Inside AuthServiceImplTest::saveRefreshTokenTest_Success1 Method");
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(user);
//			StandardPBEStringEncryptor decryptor = new StandardPBEStringEncryptor();
//			decryptor.setPassword("Done");
//			String encryptedText = decryptor.encrypt(REFRESH_TOKEN);
//			String encrypted2 = decryptor.encrypt(encryptedText);
//			String hashedRT = null;
//			hashedRT = RestUtil.get(uri + "auth-token/api/encoded-token/" + REFRESH_TOKEN, null, String.class)
//					.getBody();
//			userTokenDetails.setEncryptedRT(encrypted2);
//			userTokenDetails.setHashedRT(hashedRT);
//			user.setRefreshToken(userTokenDetails);
//			String response = authService.saveRefreshToken(REFRESH_TOKEN, VALID_USERNAME);
//			assertEquals(hashedRT, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::saveRefreshTokenTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveRefreshToken_Success2() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::saveRefreshTokenTest_Success1 Method");
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(null);
//			String response = authService.saveRefreshToken(REFRESH_TOKEN, VALID_USERNAME);
//			assertEquals(null, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::saveRefreshTokenTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveRefreshTokenAfterGLogin_Success1() {
//		try {
//			DaoUser daouser = new DaoUser();
//			daouser.setUsername(VALID_USERNAME);
//			LOGGER.debug("Inside AuthServiceImplTest::saveRefreshTokenAfterGLoginTest_Success1 Method");
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daouser);
//			StandardPBEStringEncryptor decryptor = new StandardPBEStringEncryptor();
//			decryptor.setPassword("Done");
//			String hashedRefreshToken = null;
//			hashedRefreshToken = RestUtil.get(uri + "auth-token/api/encoded-token/" + REFRESH_TOKEN, null, String.class)
//					.getBody();
//			String response = authService.saveRefreshToken(REFRESH_TOKEN, VALID_USERNAME);
//			assertEquals(hashedRefreshToken, response);
//		} catch (Exception e) {
//			LOGGER.error(
//					"Inside AuthServiceImplTest::saveRefreshTokenAfterGLoginTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveRefreshTokenAfterGLogin_Failure1() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::saveRefreshTokenAfterGLoginTest_Failure Method");
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			when(userRepo.findByUsername(VALID_USERNAME)).thenThrow(Exception.class);
//			String response = authService.saveRefreshToken(REFRESH_TOKEN, VALID_USERNAME);
//			assertEquals(null, response);
//		} catch (Exception e) {
//			LOGGER.error(
//					"Inside AuthServiceImplTest::saveRefreshTokenAfterGLoginTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateRefreshTokenTest_Success1() {
//		try {
//			DaoUser daouser = new DaoUser();
//			daouser.setRefreshToken(userTokenDetails);
//			LOGGER.debug("Inside AuthServiceImplTest::validateRefreshTokenTest_Success1 Method");
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			when(userRepo.findByHashedRT(HASHED_TOKEN)).thenReturn(daouser);
//			Boolean response = authService.validateRefreshToken(HASHED_TOKEN);
//			assertEquals(false, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::validateRefreshTokenTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void extractJwtFromRequestTest_Success1() {
//		try {
//			String Header = "Bearer Hello";
//			String token = request.getHeader(Header);
//			DaoUser daouser = new DaoUser();
//			daouser.setRefreshToken(userTokenDetails);
//			LOGGER.debug("Inside AuthServiceImplTest::extractJwtFromRequestTest_Success1 Method");
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
//				StandardPBEStringEncryptor decryptor = new StandardPBEStringEncryptor();
//				decryptor.setPassword("Done");
//				token = token.substring(7, token.length());
//				token = decryptor.decrypt(token);
//				String response = authService.extractJwtFromRequest(Mockito.<HttpServletRequest>any());
//				System.out.println(response);
//				assertEquals(token, response);
//			}
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::extractJwtFromRequestTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void extractRtFromRequestTest_Success1() {
//		try {
//			String Header = "Bearer Hello";
//			String token = request.getHeader(Header);
//			LOGGER.debug("Inside AuthServiceImplTest::extractRtFromRequestTest_Success1 Method"); // when(StringUtils.hasText(token)).thenReturn(flag);
//			if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
//				token = token.substring(7, token.length());
//				String response = authService.extractRtFromRequest(Mockito.<HttpServletRequest>any());
//				System.out.println(response);
//				assertEquals(token, response);
//			}
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::extractRtFromRequestTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void isRTPresent_Success1() {
//		try {
//			DaoUser daoUser = new DaoUser();
//			daoUser.setRefreshToken(userTokenDetails);
//			LOGGER.debug("Inside AuthServiceImplTest::isRTPresentTest_Success Method");
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			when(userRepo.findByHashedRT(HASHED_TOKEN)).thenReturn(daoUser);
//			when(daoUser.getRefreshToken().getHashedRT()).thenReturn(HASHED_TOKEN);
//			Boolean response = authService.isRTPresent(HASHED_TOKEN);
//			assertEquals(true, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::isRTPresentTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void isRTPresent_Failure1() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::isRTPresentTest_Fail Method");
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			when(userRepo.findByHashedRT(HASHED_TOKEN)).thenReturn(null);
//			Boolean response = authService.isRTPresent(HASHED_TOKEN);
//			assertEquals(false, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::isRTPresentTest_Fail method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void isRTPresent_Failure2() {
//		try {
//			DaoUser daoUser = new DaoUser();
//			daoUser.setRefreshToken(userTokenDetails);
//			LOGGER.debug("Inside AuthServiceImplTest::isRTPresentTest_Fail Method");
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			when(userRepo.findByHashedRT(HASHED_TOKEN)).thenReturn(daoUser);
//			when(daoUser.getRefreshToken().getHashedRT()).thenReturn(Mockito.anyString());
//			Boolean response = authService.isRTPresent(HASHED_TOKEN);
//			assertEquals(false, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::isRTPresentTest_Fail method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void addPasscode_Success1() {
//		try {
//			DaoUser user = new DaoUser();
//			user.setMailId(VALID_MAILID);
//			LOGGER.debug("Inside AuthServiceImplTest::addPasscodeTest_Success1 Method");
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(null);
//			BaseResponse response = authService.addPasscode(VALID_MAILID, PASSCODE);
//			assertEquals(false, response.getSuccess());
//			assertEquals("No user exists with that email.", response.getMessage());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::addPasscodeTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void addPasscode_Success2() {
//		try {
//			DaoUser user = new DaoUser();
//			user.setMailId(VALID_MAILID);
//			LOGGER.debug("Inside AuthServiceImplTest::addPasscodeTest_Success1 Method");
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(user);
//			user.setPasscode(PASSCODE);
//			BaseResponse response = authService.addPasscode(VALID_MAILID, PASSCODE);
//			assertEquals(true, response.getSuccess());
//			assertEquals("Passcode generated", response.getMessage());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::addPasscodeTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkPass_Success1() {
//		try {
//			Boolean response = authService.checkPass(RIGHT_PASSWORD, HASHED_PASS);
//			assertEquals(true, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::addPasscodeTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkForDuplicateEmail_Success1() {
//		try {
//			DaoUser daouser = new DaoUser();
//			daouser.setMailId(VALID_MAILID);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daouser);
//			Boolean response = authService.checkForDuplicateEmail(VALID_MAILID);
//			assertEquals(true, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkForDuplicateEmail_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkForDuplicateEmail_Success2() {
//		try {
//			DaoUser user = new DaoUser();
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(user);
//			Boolean response = authService.checkForDuplicateEmail(Mockito.anyString());
//			assertEquals(false, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkForDuplicateEmail_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkForDuplicateUsername_Success1() {
//		try {
//			DaoUser daouser = new DaoUser();
//			daouser.setUsername(VALID_USERNAME);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daouser);
//			Boolean response = authService.checkForDuplicateUsername(VALID_USERNAME);
//			assertEquals(true, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkForDuplicateUsername_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkForDuplicateUsername_Success2() {
//		try {
//			DaoUser user = null;
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(user);
//			Boolean response = authService.checkForDuplicateUsername(Mockito.anyString());
//			assertEquals(false, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkForDuplicateUsername_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void isValidEmail_Success1() {
//		try {
//			Boolean response = authService.isValidEmail(VALID_MAILID);
//			assertEquals(true, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::isValidEmail_Success method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void isValidEmail_Failure1() {
//		try {
//			Boolean response = authService.isValidEmail(INVALID_MAILID);
//			assertEquals(false, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::isValidEmail_Failure method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void isValidPassword_Success1() {
//		try {
//			Boolean response = authService.isValidPassword(VALID_PASSWORD);
//			assertEquals(true, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::isValidPassword_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void isValidPassword_Failure1() {
//		try {
//			Boolean response = authService.isValidPassword(INVALID_PASSWORD);
//			assertEquals(false, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::isValidPassword_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void isValidUsername_Success1() {
//		try {
//			Boolean response = authService.isValidUsername(VALID_USERNAME);
//			assertEquals(true, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::isValidUsername_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void isValidUsername_Failure1() {
//		try {
//			Boolean response = authService.isValidUsername(INVALID_USERNAME);
//			assertEquals(false, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::isValidUsername_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkForMfa_Success1() {
//		try {
//			GoogleAuthDetails gauthDetails = new GoogleAuthDetails();
//			DaoUser user = new DaoUser();
//			user.setMailId(VALID_MAILID);
//			user.setGoogleAuthDetails(gauthDetails);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(user);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkForMfa_Success method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void checkForMfa_Failure1() {
//		try {
//			Boolean response = authService.checkForMfa(null);
//			assertEquals(false, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkForMfa_Failure method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void checkMfaTest_Failure1() {
//		try {
//			DaoUser daoUser = new DaoUser();
//			daoUser.setUsername(VALID_USERNAME);
//			daoUser.setGoogleAuthDetails(null);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			GoogleAuthDetails googleAuthDetails = new GoogleAuthDetails();
//			daoUser.setGoogleAuthDetails(googleAuthDetails);
//			Boolean response = authService.checkMfa(request);
//			assertEquals(false, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkMfaTest_Success method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void savePasswordTest_Success1() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
//			DaoUser daoUser = new DaoUser();
//			daoUser.setMailId(VALID_MAILID);
//			daoUser.setPassword(RIGHT_PASSWORD);
//			changePasswordRequest.setMailId(VALID_MAILID);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			LOGGER.debug("Inside AuthServiceImplTest::savePasswordTest_Success7 Method");
//			when(userRepo.findByMailId(changePasswordRequest.getMailId())).thenReturn(null);
//			changePasswordRequest.setNewPassword(VALID_PASSWORD);
//			changePasswordRequest.setNewPassword(VALID_PASSWORD);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::savePasswordTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void savePasswordTest_Success2() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
//			DaoUser daoUser = new DaoUser();
//			daoUser.setMailId(VALID_MAILID);
//			daoUser.setPasscode(PASSCODE);
//			daoUser.setPassword(RIGHT_PASSWORD);
//			changePasswordRequest.setPasscode(PASSCODE);
//			changePasswordRequest.setMailId(VALID_MAILID);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			LOGGER.debug("Inside AuthServiceImplTest::savePasswordTest_Success7 Method");
//			when(userRepo.findByMailId(changePasswordRequest.getMailId())).thenReturn(daoUser);
//			changePasswordRequest.setNewPassword(VALID_PASSWORD);
//			changePasswordRequest.setConfirmedPassword(VALID_PASSWORD);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::savePasswordTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void savePasswordTest_Success3() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
//			DaoUser daoUser = new DaoUser();
//			daoUser.setMailId(VALID_MAILID);
//			daoUser.setUsername(VALID_USERNAME);
//			daoUser.setPasscode(PASSCODE);
//			daoUser.setPassword(RIGHT_PASSWORD);
//			changePasswordRequest.setPasscode(PASSCODE);
//			changePasswordRequest.setMailId(VALID_MAILID);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			LOGGER.debug("Inside AuthServiceImplTest::savePasswordTest_Success7 Method");
//			when(userRepo.findByMailId(changePasswordRequest.getMailId())).thenReturn(daoUser);
//			changePasswordRequest.setNewPassword(VALID_PASSWORD);
//			changePasswordRequest.setConfirmedPassword(VALID_PASSWORD);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::savePasswordTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void savePasswordTest_Success4() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
//			DaoUser daoUser = new DaoUser();
//			daoUser.setMailId(VALID_MAILID);
//			daoUser.setUsername(VALID_USERNAME);
//			daoUser.setPasscode(PASSCODE);
//			daoUser.setPassword(RIGHT_PASSWORD);
//			changePasswordRequest.setPasscode(PASSCODE);
//			changePasswordRequest.setMailId(VALID_MAILID);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			LOGGER.debug("Inside AuthServiceImplTest::savePasswordTest_Success7 Method");
//			when(userRepo.findByMailId(changePasswordRequest.getMailId())).thenReturn(daoUser);
//			changePasswordRequest.setNewPassword(VALID_PASSWORD);
//			changePasswordRequest.setConfirmedPassword(VALID_PASSWORD);
//			daoUser.setPassword(VALID_PASSWORD);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::savePasswordTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void updateUser2FATest_Success() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			String userName = "BearerHeader";
//			DaoUser daoUser = new DaoUser();
//			daoUser.setUsername(userName);
//			daoUser.setUsername(null);
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//			GoogleAuthDetails googleAuthDetails = new GoogleAuthDetails();
//			daoUser.setGoogleAuthDetails(googleAuthDetails);
//			googleAuthDetails.setIsUsing2FA(true);
//			daoUser.setGoogleAuthDetails(googleAuthDetails);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::updateUser2FATest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//
//	}
//
//	@Test
//	public void updateAndSaveUser2FATest_Success() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			String authorizationHeader = VALID_BEARER_TOKEN;
//			DaoUser daouser = new DaoUser();
//			daouser.setUsername(authorizationHeader);
//			daouser.setUsername(null);
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daouser);
//			GoogleAuthDetails googleAuthDetails = new GoogleAuthDetails();
//			daouser.setGoogleAuthDetails(googleAuthDetails);
//			googleAuthDetails.setSecret(SECRET);
//			googleAuthDetails.setIsUsing2FA(true);
//			RegisterUserResponse registerUserResponse = new RegisterUserResponse();
//			registerUserResponse.setIsMfaEnabled(true);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::updateAndSaveUser2FATest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void changePasswordTest_Failure() {
//		try {
//			DaoUser daouser = new DaoUser();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "Done");
//			StandardPBEStringEncryptor decryptor = new StandardPBEStringEncryptor();
//			decryptor.setPassword("Done");
//			ResponseEntity<Boolean> isTokenValid = new ResponseEntity<>(true, HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<Boolean>>any()))
//			.thenReturn(isTokenValid);
//			ResponseEntity<String> usernameResponse = RestUtil.get(uri + TOKEN, null, String.class);
//			String username = usernameResponse.getBody();
//			daouser.setUsername(username);
//			when(userRepo.findByUsername(username)).thenReturn(daouser);
//			daouser.setPassword(VALID_PASSWORD);
//			daouser.setPassword(NEW_PASSWORD);
//			BaseResponse response = authService.changePassword(TOKEN, VALID_PASSWORD, NEW_PASSWORD, NEW_PASSWORD);
//			assertEquals("Exception occured while changing password!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::changePasswordTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void updateAndSaveUser2FATest_Failure() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			String authorizationHeader = "Bearer Header";
//			DaoUser daouser = new DaoUser();
//			daouser.setUsername(authorizationHeader);
//			daouser.setUsername(null);
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daouser);
//			GoogleAuthDetails googleAuthDetails = new GoogleAuthDetails();
//			daouser.setGoogleAuthDetails(googleAuthDetails);
//			googleAuthDetails.setSecret(null);
//			googleAuthDetails.setIsUsing2FA(false);
//			RegisterUserResponse registerUserResponse = new RegisterUserResponse();
//			registerUserResponse.setIsMfaEnabled(true);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::updateAndSaveUser2FATest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void updateUserTest_Success() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			PowerMockito.mockStatic(StringUtils.class);
//			String authorizationHeader = VALID_BEARER_TOKEN;
//			RegistrationUser user = new RegistrationUser();
//			user.setMailId(VALID_MAILID);
//			String token = request.getHeader(authorizationHeader);
//			ResponseEntity<Boolean> usernameResponse = new ResponseEntity<Boolean>(false, HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/validate/" + token, null, Boolean.class))
//			.thenReturn(usernameResponse);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::updateUserTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void updateUserTest_Success1() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			PowerMockito.mockStatic(StringUtils.class);
//			String authorizationHeader = "Bearer Header";
//			RegistrationUser user = new RegistrationUser();
//			user.setMailId(VALID_MAILID);
//			String token = request.getHeader(authorizationHeader);
//			when(StringUtils.isEmpty(null)).thenReturn(true);
//			ResponseEntity<Boolean> usernames = new ResponseEntity<Boolean>(true, HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/validate/" + token, null, Boolean.class))
//			.thenReturn(usernames);
//
//			ResponseEntity<String> usernameResponse = new ResponseEntity<String>("", HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/username/" + token, null, String.class))
//			.thenReturn(usernameResponse);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::updateUserTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void updateUserTest_Success2() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			PowerMockito.mockStatic(StringUtils.class);
//			String authorizationHeader = "Bearer Header";
//			DaoUser daouser = new DaoUser();
//			daouser.setUsername(null);
//			String token = request.getHeader(authorizationHeader);
//			when(StringUtils.isEmpty(null)).thenReturn(true);
//			ResponseEntity<Boolean> usernames = new ResponseEntity<Boolean>(true, HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/validate/" + token, null, Boolean.class))
//			.thenReturn(usernames);
//			ResponseEntity<String> usernameResponse = new ResponseEntity<String>("Albanero", HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/username/" + token, null, String.class))
//			.thenReturn(usernameResponse);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::updateUserTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void updateUserTest_Success3() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			PowerMockito.mockStatic(StringUtils.class);
//			String authorizationHeader = "Bearer Header";
//			DaoUser daouser = new DaoUser();
//			RegisterUserResponse payload = new RegisterUserResponse();
//			RegistrationUser user = new RegistrationUser();
//			user.setMailId(VALID_MAILID);
//			user.setUsername("Albanero");
//			String token = request.getHeader(authorizationHeader);
//			when(StringUtils.isEmpty(null)).thenReturn(true);
//			ResponseEntity<Boolean> usernames = new ResponseEntity<Boolean>(true, HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/validate/" + token, null, Boolean.class))
//			.thenReturn(usernames);
//			ResponseEntity<String> usernameResponse = new ResponseEntity<String>("Albanero", HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/username/" + token, null, String.class))
//			.thenReturn(usernameResponse);
//			String users = usernameResponse.getBody();
//			daouser.setUsername(users);
//			daouser.setMailId(VALID_MAILID);
//			when(userRepo.findByUsername(users)).thenReturn(daouser);
//			System.out.println(daouser);
//			ResponseEntity<String> valid = new ResponseEntity<String>("Albanero", HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/generate-token/"
//					+ String.valueOf(3 * 24 * 60 * 60000l) + "/" + user.getMailId(), null, String.class))
//			.thenReturn(valid);
//			String verificationToken = valid.getBody();
//			daouser.setEmailVerificationCode(verificationToken);
//			daouser.setIsAccountActive(false);
//			daouser.setIsAccountApproved(false);
//			when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
//			daouser.setGoogleAuthDetails(null);
//			payload.setIsMfaEnabled(true);
//			payload.setMessage("Given email address is either incorrect or already exists!");
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::updateUserTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void updateUserTest_Success5() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			PowerMockito.mockStatic(StringUtils.class);
//			String authorizationHeader = "Bearer Header";
//			DaoUser daouser = new DaoUser();
//			RegisterUserResponse payload = new RegisterUserResponse();
//			RegistrationUser user = new RegistrationUser();
//			user.setUsername("Albanero");
//			String token = request.getHeader(authorizationHeader);
//			when(StringUtils.isEmpty(null)).thenReturn(true);
//			ResponseEntity<Boolean> usernames = new ResponseEntity<Boolean>(true, HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/validate/" + token, null, Boolean.class))
//			.thenReturn(usernames);
//			ResponseEntity<String> usernameResponse = new ResponseEntity<String>("Albanero", HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/username/" + token, null, String.class))
//			.thenReturn(usernameResponse);
//			String users = usernameResponse.getBody();
//			daouser.setUsername(users);
//			daouser.setMailId(null);
//			when(userRepo.findByUsername(users)).thenReturn(daouser);
//			System.out.println(daouser);
//			ResponseEntity<String> valid = new ResponseEntity<String>("Albanero", HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/generate-token/"
//					+ String.valueOf(3 * 24 * 60 * 60000l) + "/" + user.getMailId(), null, String.class))
//			.thenReturn(valid);
//			String verificationToken = valid.getBody();
//			daouser.setEmailVerificationCode(verificationToken);
//			daouser.setIsAccountActive(false);
//			daouser.setIsAccountApproved(false);
//			when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
//			daouser.setGoogleAuthDetails(null);
//			payload.setIsMfaEnabled(true);
//			payload.setMessage("Given email address is either incorrect or already exists!");
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::updateUserTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void updateUserTest_Failure() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			PowerMockito.mockStatic(StringUtils.class);
//			String Header = "Bearer Header";
//			DaoUser daouser = new DaoUser();
//			RegisterUserResponse payload = new RegisterUserResponse();
//			RegistrationUser user = new RegistrationUser();
//			user.setMailId(VALID_MAILID);
//			user.setUsername("Albanero");
//			String token = request.getHeader(Header);
//			when(StringUtils.isEmpty(null)).thenReturn(true);
//			when(RestUtil.get("https://www.test.comauth-token/api/validate/" + token, null, Boolean.class))
//			.thenThrow(Exception.class);
//			ResponseEntity<String> usernameResponse = new ResponseEntity<String>("Albanero", HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/username/" + token, null, String.class))
//			.thenReturn(usernameResponse);
//			String users = usernameResponse.getBody();
//			daouser.setUsername(users);
//			daouser.setMailId(null);
//			when(userRepo.findByUsername(users)).thenReturn(daouser);
//			System.out.println(daouser);
//			ResponseEntity<String> valid = new ResponseEntity<String>("Albanero", HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/generate-token/"
//					+ String.valueOf(3 * 24 * 60 * 60000l) + "/" + user.getMailId(), null, String.class))
//			.thenReturn(valid);
//			String verificationToken = valid.getBody();
//			daouser.setEmailVerificationCode(verificationToken);
//			daouser.setIsAccountActive(false);
//			daouser.setIsAccountApproved(false);
//			when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
//			GoogleAuthDetails googleAuthDetails = new GoogleAuthDetails();
//			daouser.setGoogleAuthDetails(googleAuthDetails);
//			payload.setIsMfaEnabled(true);
//			payload.setMessage("Given email address is either incorrect or already exists!");
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::updateUserTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void verifyTest_Success1() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			ResponseEntity<Boolean> valid = new ResponseEntity<Boolean>(false, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/validate/OTPTOKEN", null, Boolean.class)).thenReturn(valid);
//			BaseResponse response = authService.verify(OTP_TOKEN, VERIFICATION);
//			assertEquals("OTP has expired", response.getMessage());
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::updateAndSaveUser2FATest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void verifyTest_Success2() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			DaoUser daouser = new DaoUser();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			ResponseEntity<Boolean> valid = new ResponseEntity<Boolean>(true, HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/validate/OTPTOKEN", null, Boolean.class))
//			.thenReturn(valid);
//			Boolean verification = valid.getBody();
//			System.out.println(verification);
//			ResponseEntity<String> username = new ResponseEntity<String>("user", HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/email/OTPTOKEN", null, String.class))
//			.thenReturn(username);
//			daouser.setMailId(VALID_MAILID);
//			GoogleAuthDetails gauthDetails = new GoogleAuthDetails();
//			daouser.setGoogleAuthDetails(gauthDetails);
//			gauthDetails.setSecret("secret");
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daouser);
//			ResponseEntity<Boolean> isValidUsername = new ResponseEntity<Boolean>(false, HttpStatus.OK);
//			when(RestUtil.post("https://www.test.com/mfa/api/verify" + "/" + "hello" + "/"
//					+ daouser.getGoogleAuthDetails().getSecret(), null, null, Boolean.class))
//			.thenReturn(isValidUsername);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::updateAndSaveUser2FATest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void verifyTest_Success3() {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthResponse authResponse = new AuthResponse();
//			DaoUser daouser = new DaoUser();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			ResponseEntity<Boolean> valid = new ResponseEntity<Boolean>(true, HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/validate/OTPTOKEN", null, Boolean.class))
//			.thenReturn(valid);
//			ResponseEntity<String> username = new ResponseEntity<String>("user", HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/email/OTPTOKEN", null, String.class))
//			.thenReturn(username);
//			daouser.setMailId(VALID_USERNAME);
//			GoogleAuthDetails gauthDetails = new GoogleAuthDetails();
//			daouser.setGoogleAuthDetails(gauthDetails);
//			gauthDetails.setSecret("secret");
//			when(userRepo.findByMailId(VALID_USERNAME)).thenReturn(daouser);
//			ResponseEntity<Boolean> isValidUsername = new ResponseEntity<Boolean>(true, HttpStatus.OK);
//			when(RestUtil.post("https://www.test.com/mfa/api/verify" + "/" + VERIFICATION + "/"
//					+ daouser.getGoogleAuthDetails().getSecret(), null, null, Boolean.class))
//			.thenReturn(isValidUsername);
//			daouser.setUsername(VALID_USERNAME);
//			daouser.setRefreshToken(userTokenDetails);
//			userTokenDetails.setEncryptedRT(ENCRYPTED_RT);
//			userTokenDetails.setHashedRT(HASHED_RT);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daouser);
//			ResponseEntity<String> jwtTokenResponse = new ResponseEntity<String>("hello", HttpStatus.OK);
//			when(RestUtil.post("https://www.test.comauth-token/api/generate-token/" + "access", null, daouser,
//					String.class)).thenReturn(jwtTokenResponse);
//			ResponseEntity<String> refreshTokenResponse = new ResponseEntity<String>("token", HttpStatus.OK);
//			when(RestUtil.post("https://www.test.comauth-token/api/generate-token/" + "refresh", null, daouser,
//					String.class)).thenReturn(refreshTokenResponse);
//			String refreshToken = refreshTokenResponse.getBody();
//			daouser.setUsername(VALID_USERNAME);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daouser);
//			ResponseEntity<String> hashedToken = new ResponseEntity<String>("TOKEN", HttpStatus.OK);
//			when(RestUtil.get("https://www.test.comauth-token/api/encoded-token/" + refreshToken, null, String.class))
//			.thenReturn(hashedToken);
//			String refreshHashed = hashedToken.getBody();
//			userTokenDetails.setHashedRT(refreshHashed);
//			daouser.setRefreshToken(userTokenDetails);
//			authResponse.setRefreshToken(refreshHashed);
//			daouser.setUsername(VALID_USERNAME);
//			authResponse.setUsername(VALID_USERNAME);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::updateAndSaveUser2FATest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void loadUserByUsernameTest_Success() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::loadUserByUsernameTest_Success Method");
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(getDaoUser());
//			UserDetails response = authService.loadUserByUsername(VALID_USERNAME);
//			assertEquals(VALID_USERNAME, response.getUsername());
//			assertEquals(VALID_PASSWORD, response.getPassword());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::loadUserByUsernameTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void loadUserByUsernameTest_Failure() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::loadUserByUsernameTest_Failure Method");
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(null);
//			UserDetails response = authService.loadUserByUsername(Mockito.anyString());
//			assertEquals(null, response.getUsername());
//			assertEquals(null, response.getPassword());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::loadUserByUsernameTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void loadDaoUserByUsernameTest_Success() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::loadDaoUserByUsernameTest_Success Method");
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(getDaoUser());
//			DaoUser response = authService.loadDaoUserByUsername(VALID_USERNAME);
//			assertEquals(VALID_USERNAME, response.getUsername());
//			assertEquals(VALID_PASSWORD, response.getPassword());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::loadDaoUserByUsernameTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void loadDaoUserByUsernameTest_Failure() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::loadDaoUserByUsernameTest_Failure Method");
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(null);
//			DaoUser response = authService.loadDaoUserByUsername(Mockito.anyString());
//			assertEquals(null, response.getUsername());
//			assertEquals(null, response.getPassword());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::loadDaoUserByUsernameTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void loadDaoUserByMailIdTest_Success() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::loadDaoUserByMailIdTest_Success Method");
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(getDaoUser());
//			DaoUser response = authService.loadDaoUserByMailId(VALID_MAILID);
//			assertEquals(VALID_USERNAME, response.getUsername());
//			assertEquals(VALID_PASSWORD, response.getPassword());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::loadDaoUserByMailIdTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void loadDaoUserByMailIdTest_Failure() {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest::loadDaoUserByMailIdTest_Failure Method");
//			when(userRepo.findByMailId(Mockito.anyString())).thenReturn(null);
//			DaoUser response = authService.loadDaoUserByMailId(Mockito.anyString());
//			assertEquals(null, response.getUsername());
//			assertEquals(null, response.getPassword());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::loadDaoUserByMailIdTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void generateExternalTokenTest_Failure() throws Exception {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest:generateExternalTokenTest_Failure Method");
//			BaseResponse response = authService.generateExternalToken(null);
//			assertEquals(false, response.getSuccess());
//			assertEquals("The given user ID is either null or empty!", response.getMessage());
//			assertEquals("403", response.getStatusCode());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::generateExternalTokenTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void generateExternalTokenTest_Success() throws Exception {
//		try {
//			DaoUser daoUser = getDaoUser();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "encryptedPassword");
//			LOGGER.debug("Inside AuthServiceImplTest:generateExternalTokenTest_Success Method");
//			when(userRepo.findById(ID)).thenReturn(Optional.of(daoUser));
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any(),
//					ArgumentMatchers.any(DaoUser.class))).thenReturn(responseEntity);
//			BaseResponse response = authService.generateExternalToken(ID);
//			BasicTextEncryptor encryptor = new BasicTextEncryptor();
//			encryptor.setPassword("encryptedPassword");
//			assertEquals(true, response.getSuccess());
//			assertEquals("Token returned!", response.getMessage());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::generateExternalTokenTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void fetchEmailTest_Success() throws Exception {
//		try {
//			DaoUser daoUser = getDaoUser();
//			LOGGER.debug("Inside AuthServiceImplTest:fetchEmailTest_Success Method");
//			daoUser.setMailId(VALID_MAILID);
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			String response = authService.fetchEmail(request);
//			assertEquals(VALID_MAILID, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::fetchEmailTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void fetchEmailTest_Failure1() throws Exception {
//		try {
//			DaoUser daoUser = getDaoUser();
//			LOGGER.debug("Inside AuthServiceImplTest:fetchEmailTest_Failure1 Method");
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			String response = authService.fetchEmail(request);
//			assertEquals(null, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::fetchEmailTest_Failure1 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void fetchEmailTest_Failure2() throws Exception {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest:fetchEmailTest_Failure2 Method");
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(null);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			String response = authService.fetchEmail(request);
//			assertEquals(null, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::fetchEmailTest_Failure2 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void fetchEmailTest_Failure3() throws Exception {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest:fetchEmailTest_Failure3 Method");
//			when(userRepo.findByUsername(Mockito.anyString())).thenThrow(Exception.class);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			String response = authService.fetchEmail(request);
//			assertEquals(null, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::fetchEmailTest_Failure3 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void fetchEmailTest_Failure4() throws Exception {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest:fetchEmailTest_Failure4 Method");
//			when(discoveryClient.getInstances(Mockito.anyString())).thenThrow(Exception.class);
//			String response = authService.fetchEmail(request);
//			assertEquals(null, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::fetchEmailTest_Failure4 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void fetchEmailTest_Failure5() throws Exception {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest:fetchEmailTest_Failure5 Method");
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenThrow(Exception.class);
//			String response = authService.fetchEmail(request);
//			assertEquals(null, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::fetchEmailTest_Failure5 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	//	@Test
//	//	public void removeProductMemberTest_Failure1() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeProductMemberTest_Failure1 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenThrow(Exception.class);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeProductMember(request, null);
//	//			assertEquals("Exception occured in adding a member.", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeProductMemberTest_Failure1 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeProductMemberTest_Failure2() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeProductMemberTest_Failure2 Method");
//	//			when(discoveryClient.getInstances(Mockito.anyString())).thenThrow(Exception.class);
//	//			BaseResponse response = authService.removeProductMember(request, null);
//	//			assertEquals("Exception occured in adding a member.", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeProductMemberTest_Failure2 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeProductMemberTest_Failure3() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeProductMemberTest_Failure3 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(null);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeProductMember(request, getAddMemberRequest());
//	//			assertEquals("This user does not have access to this product", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeProductMemberTest_Failure3 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeProductMemberTest_Failure4() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeProductMemberTest_Failure4 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeProductMember(request, getAddMemberRequest());
//	//			assertEquals("This user does not have access to this product", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeProductMemberTest_Failure4 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeProductMemberTest_Failure5() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeProductMemberTest_Failure5 Method");
//	//			userRoleDetails.setProduct(null);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeProductMember(request, getAddMemberRequest());
//	//			assertEquals("This user does not have access to this product", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeProductMemberTest_Failure5 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeProductMemberTest_Failure6() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			Product product = getProduct();
//	//			ProductRoleDetails productRoleDetails = getProductRoleDetails();
//	//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeProductMemberTest_Failure6 Method");
//	//			productRoleDetailsList.add(productRoleDetails);
//	//			userRoleDetails.setProduct(productRoleDetailsList);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(productRepo.findByProductId(Mockito.anyString())).thenReturn(product);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeProductMember(request, getAddMemberRequest());
//	//			assertEquals("This user does not have access to this product", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeProductMemberTest_Failure6 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeProductMemberTest_Failure7() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			Product product = getProduct();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			ProductRoleDetails productRoleDetails = getProductRoleDetails();
//	//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeProductMemberTest_Failure7 Method");
//	//			product.setProductId(ID);
//	//			addMemberRequest.setRole("ef");
//	//			productRoleDetailsList.add(productRoleDetails);
//	//			userRoleDetails.setProduct(productRoleDetailsList);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(productRepo.findByProductId(Mockito.anyString())).thenReturn(product);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeProductMember(request, addMemberRequest);
//	//			assertEquals("This user role does not exist.", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeProductMemberTest_Failure7 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeProductMemberTest_Success1() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			Product product = getProduct();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			ProductRoleDetails productRoleDetails = getProductRoleDetails();
//	//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeProductMemberTest_Success1 Method");
//	//			product.setProductId(ID);
//	//			productRoleDetailsList.add(productRoleDetails);
//	//			userRoleDetails.setProduct(productRoleDetailsList);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(productRepo.findByProductId(Mockito.anyString())).thenReturn(product);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeProductMember(request, addMemberRequest);
//	//			assertEquals("Succesfully removed member from the product space", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeProductMemberTest_Success1 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeProductMemberTest_Success2() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			Product product = getProduct();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			ProductRoleDetails productRoleDetails = getProductRoleDetails();
//	//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeProductMemberTest_Success2 Method");
//	//			product.setProductId(ID);
//	//			addMemberRequest.setRole("member");
//	//			productRoleDetailsList.add(productRoleDetails);
//	//			userRoleDetails.setProduct(productRoleDetailsList);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(productRepo.findByProductId(Mockito.anyString())).thenReturn(product);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeProductMember(request, addMemberRequest);
//	//			assertEquals("Succesfully removed member from the product space", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeProductMemberTest_Success2 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addProductMemberTest_Failure1() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:addProductMemberTest_Failure1 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenThrow(Exception.class);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addProductMember(request, null);
//	//			assertEquals("Exception occured in adding a member.", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addProductMemberTest_Failure1 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addProductMemberTest_Failure2() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:addProductMemberTest_Failure2 Method");
//	//			when(discoveryClient.getInstances(Mockito.anyString())).thenThrow(Exception.class);
//	//			BaseResponse response = authService.addProductMember(request, null);
//	//			assertEquals("Exception occured in adding a member.", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addProductMemberTest_Failure2 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addProductMemberTest_Failure3() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:addProductMemberTest_Failure3 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(null);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addProductMember(request, getAddMemberRequest());
//	//			assertEquals("This user does not have access to this product", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addProductMemberTest_Failure3 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addProductMemberTest_Failure4() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			LOGGER.debug("Inside AuthServiceImplTest:addProductMemberTest_Failure4 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addProductMember(request, getAddMemberRequest());
//	//			assertEquals("This user does not have access to this product", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addProductMemberTest_Failure4 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addProductMemberTest_Failure5() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			LOGGER.debug("Inside AuthServiceImplTest:addProductMemberTest_Failure5 Method");
//	//			userRoleDetails.setProduct(null);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addProductMember(request, getAddMemberRequest());
//	//			assertEquals("This user does not have access to this product", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addProductMemberTest_Failure5 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addProductMemberTest_Failure6() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			Product product = getProduct();
//	//			ProductRoleDetails productRoleDetails = getProductRoleDetails();
//	//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//	//			LOGGER.debug("Inside AuthServiceImplTest:addProductMemberTest_Failure6 Method");
//	//			productRoleDetailsList.add(productRoleDetails);
//	//			userRoleDetails.setProduct(productRoleDetailsList);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(productRepo.findByProductId(Mockito.anyString())).thenReturn(product);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addProductMember(request, getAddMemberRequest());
//	//			assertEquals("This user does not have access to this product", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addProductMemberTest_Failure6 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addProductMemberTest_Failure7() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			Product product = getProduct();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			ProductRoleDetails productRoleDetails = getProductRoleDetails();
//	//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//	//			LOGGER.debug("Inside AuthServiceImplTest:addProductMemberTest_Failure7 Method");
//	//			product.setProductId(ID);
//	//			addMemberRequest.setRole("ef");
//	//			productRoleDetailsList.add(productRoleDetails);
//	//			userRoleDetails.setProduct(productRoleDetailsList);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(productRepo.findByProductId(Mockito.anyString())).thenReturn(product);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addProductMember(request, addMemberRequest);
//	//			assertEquals("This user role does not exist.", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addProductMemberTest_Failure7 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addProductMemberTest_Success1() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			Product product = getProduct();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			ProductRoleDetails productRoleDetails = getProductRoleDetails();
//	//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//	//			LOGGER.debug("Inside AuthServiceImplTest:addProductMemberTest_Success1 Method");
//	//			product.setProductId(ID);
//	//			productRoleDetailsList.add(productRoleDetails);
//	//			userRoleDetails.setProduct(productRoleDetailsList);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(productRepo.findByProductId(Mockito.anyString())).thenReturn(product);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addProductMember(request, addMemberRequest);
//	//			assertEquals("Succesfully added member to the product space", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addProductMemberTest_Success1 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addProductMemberTest_Success2() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			Product product = getProduct();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			ProductRoleDetails productRoleDetails = getProductRoleDetails();
//	//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//	//			LOGGER.debug("Inside AuthServiceImplTest:addProductMemberTest_Success2 Method");
//	//			product.setProductId(ID);
//	//			addMemberRequest.setRole("member");
//	//			productRoleDetailsList.add(productRoleDetails);
//	//			userRoleDetails.setProduct(productRoleDetailsList);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(productRepo.findByProductId(Mockito.anyString())).thenReturn(product);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addProductMember(request, addMemberRequest);
//	//			assertEquals("Succesfully added member to the product space", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addProductMemberTest_Success2 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//
//	@Test
//	public void fetchUsernameTest_Failure() throws Exception {
//		try {
//			DaoUser daoUser1 = getDaoUser();
//			DaoUser daoUser2 = getDaoUser();
//			LOGGER.debug("Inside AuthServiceImplTest:fetchUsernameTest_Failure Method");
//			daoUser2.setId("Id");
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser1);
//			when(userRepo.findById(Mockito.anyString())).thenReturn(Optional.of(daoUser2));
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			BaseResponse response = authService.fetchUsername(request, ID);
//			assertEquals("The provided token doesn't belong to the given user.", response.getMessage());
//			assertEquals("403", response.getStatusCode());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::fetchUsernameTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void fetchUsernameTest_Success() throws Exception {
//		try {
//			DaoUser daoUser = getDaoUser();
//			LOGGER.debug("Inside AuthServiceImplTest:fetchUsernameTest_Success Method");
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//			when(userRepo.findById(Mockito.anyString())).thenReturn(Optional.of(daoUser));
//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			BaseResponse response = authService.fetchUsername(request, ID);
//			assertEquals("Username fetched!", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::fetchUsernameTest_Failure1 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getProductDetailsTest_Failure1() throws Exception {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest:getProductDetailsTest_Failure1 Method");
//			when(userRepo.findByUsername(Mockito.anyString())).thenThrow(Exception.class);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			BaseResponse response = authService.getProductDetails(request);
//			assertEquals("Exception occured in fetching the product details!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::getProductDetailsTest_Failure1 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getProductDetailsTest_Failure2() throws Exception {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest:getProductDetailsTest_Failure2 Method");
//			when(discoveryClient.getInstances(Mockito.anyString())).thenThrow(Exception.class);
//			BaseResponse response = authService.getProductDetails(request);
//			assertEquals("Exception occured in fetching the product details!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::getProductDetailsTest_Failure2 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getProductDetailsTest_Failure3() throws Exception {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest:getProductDetailsTest_Failure3 Method");
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(null);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			BaseResponse response = authService.getProductDetails(request);
//			assertEquals("User not found!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::getProductDetailsTest_Failure3 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getProductDetailsTest_Failure4() throws Exception {
//		try {
//			DaoUser daoUser = getDaoUser();
//			LOGGER.debug("Inside AuthServiceImplTest:getProductDetailsTest_Failure4 Method");
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			BaseResponse response = authService.getProductDetails(request);
//			assertEquals("User not found!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::getProductDetailsTest_Failure4 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getProductDetailsTest_Failure5() throws Exception {
//		try {
//			DaoUser daoUser = getDaoUser();
//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//			LOGGER.debug("Inside AuthServiceImplTest:getProductDetailsTest_Failure5 Method");
//			userRoleDetails.setProduct(null);
//			daoUser.setUserRole(userRoleDetails);
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			BaseResponse response = authService.getProductDetails(request);
//			assertEquals("User not found!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::getProductDetailsTest_Failure5 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getProductDetailsTest_Failure6() throws Exception {
//		try {
//			DaoUser daoUser = getDaoUser();
//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//			Product product = getProduct();
//			List<Product> productList = new ArrayList();
//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//			LOGGER.debug("Inside AuthServiceImplTest:getProductDetailsTest_Failure6 Method");
//			userRoleDetails.setProduct(productRoleDetailsList);
//			daoUser.setUserRole(userRoleDetails);
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//			when(productRepo.findAll()).thenReturn(productList);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			BaseResponse response = authService.getProductDetails(request);
//			assertEquals("There are no products available as of now.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::getProductDetailsTest_Failure6 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getProductDetailsTest_Success() throws Exception {
//		try {
//			DaoUser daoUser = getDaoUser();
//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//			Product product = getProduct();
//			List<Product> productList = new ArrayList();
//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//			LOGGER.debug("Inside AuthServiceImplTest:getProductDetailsTest_Success Method");
//			productList.add(product);
//			userRoleDetails.setProduct(productRoleDetailsList);
//			daoUser.setUserRole(userRoleDetails);
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//			when(productRepo.findAll()).thenReturn(productList);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			BaseResponse response = authService.getProductDetails(request);
//			assertEquals("Successfully fetched product details!", response.getMessage());
//			assertEquals(true, response.getSuccess());
//			assertEquals(productList, response.getPayload());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::getProductDetailsTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void verifyUserAccessTest_Failure1() throws Exception {
//		try {
//			DaoUser daoUser = getDaoUser();
//			LOGGER.debug("Inside AuthServiceImplTest:verifyUserAccessTest_Failure1 Method");
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			Boolean response = authService.verifyUserAccess(request, ID);
//			assertEquals(false, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::verifyUserAccessTest_Failure1 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void verifyUserAccessTest_Failure2() throws Exception {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest:verifyUserAccessTest_Failure2 Method");
//			when(userRepo.findByUsername(Mockito.anyString())).thenThrow(Exception.class);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			Boolean response = authService.verifyUserAccess(request, ID);
//			assertEquals(false, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::verifyUserAccessTest_Failure2 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void verifyUserAccessTest_Failure3() throws Exception {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest:verifyUserAccessTest_Failure3 Method");
//			when(discoveryClient.getInstances(Mockito.anyString())).thenThrow(Exception.class);
//			Boolean response = authService.verifyUserAccess(request, ID);
//			assertEquals(false, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::verifyUserAccessTest_Failure3 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void verifyUserAccessTest_Failure4() throws Exception {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest:verifyUserAccessTest_Failure4 Method");
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenThrow(Exception.class);
//			Boolean response = authService.verifyUserAccess(request, ID);
//			assertEquals(false, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::verifyUserAccessTest_Failure4 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void verifyUserAccessTest_Success() throws Exception {
//		try {
//			DaoUser daoUser = getDaoUser();
//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//			LOGGER.debug("Inside AuthServiceImplTest:verifyUserAccessTest_Success Method");
//			productRoleDetailsList.add(getProductRoleDetails());
//			userRoleDetails.setProduct(productRoleDetailsList);
//			daoUser.setUserRole(userRoleDetails);
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			Boolean response = authService.verifyUserAccess(request, ID);
//			assertEquals(true, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::verifyUserAccessTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	//	@Test
//	//	public void checkForOrgLevelDetailsTest_Success1() throws Exception {
//	//		try {
//	//			Organization organization = getOrganization();
//	//			LOGGER.debug("Inside AuthServiceImplTest:checkForOrgLevelDetailsTest_Success1 Method");
//	//			organization.setOrgId(ID);
//	//			list.add(VALID_USERNAME);
//	//			organization.setAdmin(list);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			OrgLevelDetails response = authService.checkForOrgLevelDetails(ID, VALID_USERNAME);
//	//			assertEquals(true, response.getIsAdmin());
//	//			assertEquals("ADMIN", response.getRole());
//	//			assertEquals(null, response.getOrgName());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::checkForOrgLevelDetailsTest_Success1 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void checkForOrgLevelDetailsTest_Success2() throws Exception {
//	//		try {
//	//			Organization organization = getOrganization();
//	//			List<String> list1 = new ArrayList();
//	//			LOGGER.debug("Inside AuthServiceImplTest:checkForOrgLevelDetailsTest_Success2 Method");
//	//			organization.setOrgId(ID);
//	//			organization.setAdmin(list1);
//	//			list.add(VALID_USERNAME);
//	//			organization.setMember(list);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			OrgLevelDetails response = authService.checkForOrgLevelDetails(ID, VALID_USERNAME);
//	//			assertEquals(false, response.getIsAdmin());
//	//			assertEquals("MEMBER", response.getRole());
//	//			assertEquals(null, response.getOrgName());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::checkForOrgLevelDetailsTest_Success2 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void checkForOrgLevelDetailsTest_Failure1() throws Exception {
//	//		try {
//	//			Organization organization = getOrganization();
//	//			LOGGER.debug("Inside AuthServiceImplTest:checkForOrgLevelDetailsTest_Failure1 Method");
//	//			organization.setOrgId(ID);
//	//			organization.setAdmin(list);
//	//			organization.setMember(list);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			OrgLevelDetails response = authService.checkForOrgLevelDetails(ID, VALID_USERNAME);
//	//			assertEquals(null, response);
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::checkForOrgLevelDetailsTest_Failure1 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//
//	@Test
//	public void checkForOrgLevelDetailsTest_Failure2() throws Exception {
//		try {
//			LOGGER.debug("Inside AuthServiceImplTest:checkForOrgLevelDetailsTest_Failure2 Method");
//			//			when(orgRepo.findByOrgId(Mockito.anyString())).thenThrow(Exception.class);
//			OrgLevelDetails response = authService.checkForOrgLevelDetails(ID, VALID_USERNAME);
//			assertEquals(null, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkForOrgLevelDetailsTest_Failure2 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	//	@Test
//	//	public void createOrganizationTest_Failure1() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:createOrganizationTest_Failure1 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenThrow(Exception.class);
//	//			BaseResponse response = authService.createOrganization(request, ORG_NAME);
//	//			assertEquals("Exception occured in creating the Organization!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::createOrganizationTest_Failure1 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void createOrganizationTest_Failure2() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:createOrganizationTest_Failure2 Method");
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenThrow(Exception.class);
//	//			BaseResponse response = authService.createOrganization(request, ORG_NAME);
//	//			assertEquals("Exception occured in creating the Organization!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::createOrganizationTest_Failure2 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void createOrganizationTest_Failure3() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:createOrganizationTest_Failure3 Method");
//	//			when(discoveryClient.getInstances(Mockito.anyString())).thenThrow(Exception.class);
//	//			BaseResponse response = authService.createOrganization(request, ORG_NAME);
//	//			assertEquals("Exception occured in creating the Organization!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::createOrganizationTest_Failure3 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void createOrganizationTest_Success() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			LOGGER.debug("Inside AuthServiceImplTest:createOrganizationTest_Success Method");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.createOrganization(request, ORG_NAME);
//	//			assertEquals("Successfully created the Organization!", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::createOrganizationTest_Success method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//
//	@Test
//	public void getUserTest_Failure1() throws Exception {
//		try {
//			RegistrationUser registrationUser = getRegistrationUser();
//			LOGGER.debug("Inside AuthServiceImplTest:getUserTest_Failure1 Method");
//			when(userRepo.findByUsername(Mockito.anyString())).thenThrow(Exception.class);
//			RegistrationUser response = authService.getUser(request);
//			assertEquals(registrationUser, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::getUsersTest_Failure1 method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void getUserTest_Failure2() throws Exception {
//		try {
//			RegistrationUser registrationUser = getRegistrationUser();
//			LOGGER.debug("Inside AuthServiceImplTest:getUserTest_Failure2 Method");
//			when(discoveryClient.getInstances(Mockito.anyString())).thenThrow(Exception.class);
//			RegistrationUser response = authService.getUser(request);
//			assertEquals(registrationUser, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::getUserTest_Failure2 method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void getUserTest_Success1() throws Exception {
//		try {
//			DaoUser daoUser = getDaoUser();
//			RegistrationUser registrationUser = getRegistrationUser();
//			registrationUser.setFirstName(FIRST_NAME);
//			registrationUser.setLastName(LAST_NAME);
//			LOGGER.debug("Inside AuthServiceImplTest:getUserTest_Success1 Method");
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			RegistrationUser response = authService.getUser(request);
//			assertEquals(registrationUser, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::getUsersTest_Success1 method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void getUserTest_Success2() throws Exception {
//		try {
//			DaoUser daoUser = getDaoUser();
//			RegistrationUser registrationUser = getRegistrationUser();
//			GoogleAuthDetails googleAuthDetails = getGoogleAuthDetails();
//			registrationUser.setFirstName(FIRST_NAME);
//			registrationUser.setLastName(LAST_NAME);
//			registrationUser.setIsUsing2FA(true);
//			LOGGER.debug("Inside AuthServiceImplTest:getUserTest_Success2 Method");
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//			daoUser.setGoogleAuthDetails(googleAuthDetails);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			RegistrationUser response = authService.getUser(request);
//			assertEquals(registrationUser, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::getUsersTest_Success2 method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void generateSecretKeyTest() {
//		LOGGER.debug("Inside AuthServiceImplTest:generateSecretKeyTest Method");
//		String response = authService.generateSecretKey();
//		assertEquals(16, response.length());
//	}
//
//	@Test
//	public void checkForProductLevelDetailsTest() throws Exception {
//		try {
//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//			List<ProductRoles> productRolesList = new ArrayList();
//			Product product = getProduct();
//			ProductRoleDetails productRoleDetails = getProductRoleDetails();
//			productRoleDetailsList.add(productRoleDetails);
//			productRolesList.add(getProductRoles());
//			LOGGER.debug("Inside AuthServiceImplTest:checkForProductLevelDetailsTest Method");
//			when(productRepo.findByProductId(Mockito.anyString())).thenReturn(product);
//			List<ProductRoles> response = authService.checkForProductLevelDetails(productRoleDetailsList);
//			assertEquals(productRolesList, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkForProductLevelDetailsTest method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	//	@Test
//	//	public void updateOrganizationTest_Failure1() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:updateOrganizationTest_Failure1 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenThrow(Exception.class);
//	//			BaseResponse response = authService.updateOrganization(request, ORG_NAME);
//	//			assertEquals("Exception occured in updating the Organization!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::updateOrganizationTest_Failure1 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void updateOrganizationTest_Failure2() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:updateOrganizationTest_Failure2 Method");
//	//			when(discoveryClient.getInstances(Mockito.anyString())).thenThrow(Exception.class);
//	//			BaseResponse response = authService.updateOrganization(request, ORG_NAME);
//	//			assertEquals("Exception occured in updating the Organization!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::updateOrganizationTest_Failure2 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void updateOrganizationTest_Failure3() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			Organization organization = getOrganization();
//	//			LOGGER.debug("Inside AuthServiceImplTest:updateOrganizationTest_Failure3 Method");
//	//			organization.setAdmin(list);
//	//			userRoleDetails.setOrgId(ID);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.updateOrganization(request, ORG_NAME);
//	//			assertEquals("This user is not an Org Admin and doesn't have the permission to edit!",
//	//					response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::updateOrganizationTest_Failure3 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void updateOrganizationTest_Success1() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			LOGGER.debug("Inside AuthServiceImplTest:updateOrganizationTest_Success1 Method");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(null);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.updateOrganization(request, ORG_NAME);
//	//			assertEquals("Successfully updated the Organization!", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::updateOrganizationTest_Success1 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void updateOrganizationTest_Success2() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			LOGGER.debug("Inside AuthServiceImplTest:updateOrganizationTest_Success2 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.updateOrganization(request, ORG_NAME);
//	//			assertEquals("Successfully updated the Organization!", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::updateOrganizationTest_Success2 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void updateOrganizationTest_Success3() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			LOGGER.debug("Inside AuthServiceImplTest:updateOrganizationTest_Success3 Method");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.updateOrganization(request, ORG_NAME);
//	//			assertEquals("Successfully updated the Organization!", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::updateOrganizationTest_Success3 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void updateOrganizationTest_Success4() throws Exception {
//	//		try {
//	//			PowerMockito.mockStatic(RestUtil.class);
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			Organization organization = getOrganization();
//	//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//	//			LOGGER.debug("Inside AuthServiceImplTest:updateOrganizationTest_Success4 Method");
//	//			list.add(VALID_USERNAME);
//	//			organization.setAdmin(list);
//	//			userRoleDetails.setOrgId(ID);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//	//			when(RestUtil.get(uri + "auth-token/api/username" + "/" + VALID_USERNAME, null, String.class))
//	//					.thenReturn(responseEntity);
//	//			BaseResponse response = authService.updateOrganization(request, ORG_NAME);
//	//			assertEquals("Successfully updated the Organization!", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::updateOrganizationTest_Success4 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void getOrganizationDetailsTest_Failure1() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:getOrganizationDetailsTest_Failure1 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenThrow(Exception.class);
//	//			BaseResponse response = authService.getOrganizationDetails(request);
//	//			assertEquals("Exception occured in fetching the Organization details!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::getOrganizationDetailsTest_Failure1 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void getOrganizationDetailsTest_Failure2() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:getOrganizationDetailsTest_Failure2 Method");
//	//			when(discoveryClient.getInstances(Mockito.anyString())).thenThrow(Exception.class);
//	//			BaseResponse response = authService.getOrganizationDetails(request);
//	//			assertEquals("Exception occured in fetching the Organization details!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::getOrganizationDetailsTest_Failure2 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void getOrganizationDetailsTest_Failure3() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			LOGGER.debug("Inside AuthServiceImplTest:getOrganizationDetailsTest_Failure3 Method");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(null);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.getOrganizationDetails(request);
//	//			assertEquals("User not found!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::getOrganizationDetailsTest_Failure3 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void getOrganizationDetailsTest_Failure4() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			LOGGER.debug("Inside AuthServiceImplTest:getOrganizationDetailsTest_Failure4 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.getOrganizationDetails(request);
//	//			assertEquals("User not found!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::getOrganizationDetailsTest_Failure4 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void getOrganizationDetailsTest_Failure5() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			LOGGER.debug("Inside AuthServiceImplTest:getOrganizationDetailsTest_Failure5 Method");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.getOrganizationDetails(request);
//	//			assertEquals("User not found!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::getOrganizationDetailsTest_Failure5 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void getOrganizationDetailsTest_Failure6() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			Organization organization = getOrganization();
//	//			LOGGER.debug("Inside AuthServiceImplTest:getOrganizationDetailsTest_Failure6 Method");
//	//			organization.setAdmin(list);
//	//			organization.setMember(list);
//	//			userRoleDetails.setOrgId(ID);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.getOrganizationDetails(request);
//	//			assertEquals("This user is not an Org Admin or Member and doesn't have the permission to access this page!",
//	//					response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::getOrganizationDetailsTest_Failure6 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void getOrganizationDetailsTest_Failure7() throws Exception {
//	//		try {
//	//			PowerMockito.mockStatic(RestUtil.class);
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//	//			Organization organization = getOrganization();
//	//			List<String> stringList = new ArrayList();
//	//			stringList.add(VALID_USERNAME);
//	//			LOGGER.debug("Inside AuthServiceImplTest:getOrganizationDetailsTest_Failure7 Method");
//	//			organization.setAdmin(stringList);
//	//			organization.setMember(list);
//	//			userRoleDetails.setOrgId(ID);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//	//			when(RestUtil.get("http://aman.netauth-token/api/username" + "/" + VALID_USERNAME, null, String.class))
//	//					.thenReturn(responseEntity);
//	//			BaseResponse response = authService.getOrganizationDetails(request);
//	//			assertEquals("Exception occured in fetching the Organization details!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//			assertEquals(null, response.getPayload());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::getOrganizationDetailsTest_Failure7 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void getOrganizationDetailsTest_Success1() throws Exception {
//	//		try {
//	//			PowerMockito.mockStatic(RestUtil.class);
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//	//			Organization organization = getOrganization();
//	//			List<String> stringList = new ArrayList();
//	//			stringList.add(VALID_USERNAME);
//	//			LOGGER.debug("Inside AuthServiceImplTest:getOrganizationDetailsTest_Success1 Method");
//	//			organization.setAdmin(stringList);
//	//			organization.setMember(list);
//	//			organization.setName(ORG_NAME);
//	//			userRoleDetails.setOrgId(ID);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//	//			when(RestUtil.get(uri + "auth-token/api/username" + "/" + VALID_USERNAME, null, String.class))
//	//					.thenReturn(responseEntity);
//	//			BaseResponse response = authService.getOrganizationDetails(request);
//	//			assertEquals("Successfully fetched organization details!", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//			assertEquals(ORG_NAME, response.getPayload());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::getOrganizationDetailsTest_Success1 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void getOrganizationDetailsTest_Success2() throws Exception {
//	//		try {
//	//			PowerMockito.mockStatic(RestUtil.class);
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			Organization organization = getOrganization();
//	//			List<String> stringList = new ArrayList();
//	//			stringList.add(VALID_USERNAME);
//	//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//	//			LOGGER.debug("Inside AuthServiceImplTest:getOrganizationDetailsTest_Success2 Method");
//	//			organization.setAdmin(list);
//	//			organization.setMember(stringList);
//	//			organization.setName(ORG_NAME);
//	//			userRoleDetails.setOrgId(ID);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//	//			when(RestUtil.get(uri + "auth-token/api/username" + "/" + VALID_USERNAME, null, String.class))
//	//					.thenReturn(responseEntity);
//	//			BaseResponse response = authService.getOrganizationDetails(request);
//	//			assertEquals("Successfully fetched organization details!", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//			assertEquals(ORG_NAME, response.getPayload());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::getOrganizationDetailsTest_Success2 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addOrgMemberTest_Failure1() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:addOrgMemberTest_Failure1 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenThrow(Exception.class);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addOrgMember(request, null);
//	//			assertEquals("Exception occured in adding a member.", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addOrgMemberTest_Failure1 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addOrgMemberTest_Failure2() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:addOrgMemberTest_Failure2 Method");
//	//			when(discoveryClient.getInstances(Mockito.anyString())).thenThrow(Exception.class);
//	//			BaseResponse response = authService.addOrgMember(request, null);
//	//			assertEquals("Exception occured in adding a member.", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addOrgMemberTest_Failure2 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addOrgMemberTest_Failure3() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:addOrgMemberTest_Failure3 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(null);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addOrgMember(request, getAddMemberRequest());
//	//			assertEquals("This user is either incorrect or doesn't own this organization!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addOrgMemberTest_Failure3 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addOrgMemberTest_Failure4() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			LOGGER.debug("Inside AuthServiceImplTest:addOrgMemberTest_Failure4 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addOrgMember(request, getAddMemberRequest());
//	//			assertEquals("This user is either incorrect or doesn't own this organization!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addOrgMemberTest_Failure4 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addOrgMemberTest_Failure5() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			LOGGER.debug("Inside AuthServiceImplTest:addOrgMemberTest_Failure5 Method");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addOrgMember(request, getAddMemberRequest());
//	//			assertEquals("This user is either incorrect or doesn't own this organization!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addOrgMemberTest_Failure5 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addOrgMemberTest_Failure6() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			LOGGER.debug("Inside AuthServiceImplTest:addOrgMemberTest_Failure6 Method");
//	//			userRoleDetails.setOrgId(ID);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addOrgMember(request, getAddMemberRequest());
//	//			assertEquals("This user is either incorrect or doesn't own this organization!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addOrgMemberTest_Failure6 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addOrgMemberTest_Failure7() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			Organization organization = getOrganization();
//	//			LOGGER.debug("Inside AuthServiceImplTest:addOrgMemberTest_Failure7 Method");
//	//			addMemberRequest.setOrgId(ID);
//	//			userRoleDetails.setOrgId(ID);
//	//			organization.setAdmin(list);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addOrgMember(request, addMemberRequest);
//	//			assertEquals(
//	//					"This user is not an Admin of the given organization and doesn't have the permission to add or remove members!",
//	//					response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addOrgMemberTest_Failure7 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addOrgMemberTest_Failure8() throws Exception {
//	//		try {
//	//			PowerMockito.mockStatic(RestUtil.class);
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			Organization organization = getOrganization();
//	//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//	//			LOGGER.debug("Inside AuthServiceImplTest:addOrgMemberTest_Failure8 Method");
//	//			list.add(VALID_USERNAME);
//	//			addMemberRequest.setOrgId(ID);
//	//			userRoleDetails.setOrgId(ID);
//	//			organization.setAdmin(list);
//	//			addMemberRequest.setRole("f5y5");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			when(userRepo.findByUsername(addMemberRequest.getUsername())).thenReturn(daoUser);
//	//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//	//			when(RestUtil.get(uri + "auth-token/api/username" + "/" + VALID_USERNAME, null, String.class))
//	//					.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addOrgMember(request, addMemberRequest);
//	//			assertEquals("The given role is not supported.", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addOrgMemberTest_Failure8 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addOrgMemberTest_Failure9() throws Exception {
//	//		try {
//	//			PowerMockito.mockStatic(RestUtil.class);
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			Organization organization = getOrganization();
//	//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//	//			LOGGER.debug("Inside AuthServiceImplTest:addOrgMemberTest_Failure9 Method");
//	//			list.add(VALID_USERNAME);
//	//			addMemberRequest.setOrgId(ID);
//	//			userRoleDetails.setOrgId(ID);
//	//			organization.setAdmin(list);
//	//			addMemberRequest.setRole("f5y5");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			when(userRepo.findByUsername(addMemberRequest.getUsername())).thenReturn(null);
//	//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//	//			when(RestUtil.get(uri + "auth-token/api/username" + "/" + VALID_USERNAME, null, String.class))
//	//					.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addOrgMember(request, addMemberRequest);
//	//			assertEquals("The provided username is either incorrect or not registered!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addOrgMemberTest_Failure9 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addOrgMemberTest_Success1() throws Exception {
//	//		try {
//	//			PowerMockito.mockStatic(RestUtil.class);
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			Organization organization = getOrganization();
//	//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//	//			LOGGER.debug("Inside AuthServiceImplTest:addOrgMemberTest_Success1 Method");
//	//			addMemberRequest.setOrgId(ID);
//	//			list.add(VALID_USERNAME);
//	//			userRoleDetails.setOrgId(ID);
//	//			organization.setAdmin(list);
//	//			addMemberRequest.setRole("ADMIN");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			when(userRepo.findByUsername(addMemberRequest.getUsername())).thenReturn(daoUser);
//	//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//	//			when(RestUtil.get(uri + "auth-token/api/username" + "/" + VALID_USERNAME, null, String.class))
//	//					.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addOrgMember(request, addMemberRequest);
//	//			assertEquals("Member has been added successfully!", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addOrgMemberTest_Success1 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void addOrgMemberTest_Success2() throws Exception {
//	//		try {
//	//			PowerMockito.mockStatic(RestUtil.class);
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			Organization organization = getOrganization();
//	//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//	//			LOGGER.debug("Inside AuthServiceImplTest:addOrgMemberTest_Success2 Method");
//	//			addMemberRequest.setOrgId(ID);
//	//			list.add(VALID_USERNAME);
//	//			userRoleDetails.setOrgId(ID);
//	//			organization.setAdmin(list);
//	//			addMemberRequest.setRole("MEMBER");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			when(userRepo.findByUsername(addMemberRequest.getUsername())).thenReturn(daoUser);
//	//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//	//			when(RestUtil.get(uri + "auth-token/api/username" + "/" + VALID_USERNAME, null, String.class))
//	//					.thenReturn(responseEntity);
//	//			BaseResponse response = authService.addOrgMember(request, addMemberRequest);
//	//			assertEquals("Member has been added successfully!", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::addOrgMemberTest_Success2 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeOrgMemberTest_Failure1() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeOrgMemberTest_Failure1 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenThrow(Exception.class);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeOrgMember(request, null);
//	//			assertEquals("Exception occured in removing a member.", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeOrgMemberTest_Failure1 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeOrgMemberTest_Failure2() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeOrgMemberTest_Failure2 Method");
//	//			when(discoveryClient.getInstances(Mockito.anyString())).thenThrow(Exception.class);
//	//			BaseResponse response = authService.removeOrgMember(request, null);
//	//			assertEquals("Exception occured in removing a member.", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeOrgMemberTest_Failure2 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeOrgMemberTest_Failure3() throws Exception {
//	//		try {
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeOrgMemberTest_Failure3 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(null);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeOrgMember(request, getAddMemberRequest());
//	//			assertEquals("This user is either incorrect or doesn't own this organization!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeOrgMemberTest_Failure3 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeOrgMemberTest_Failure4() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeOrgMemberTest_Failure4 Method");
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeOrgMember(request, getAddMemberRequest());
//	//			assertEquals("This user is either incorrect or doesn't own this organization!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeOrgMemberTest_Failure4 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeOrgMemberTest_Failure5() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeOrgMemberTest_Failure5 Method");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeOrgMember(request, getAddMemberRequest());
//	//			assertEquals("This user is either incorrect or doesn't own this organization!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeOrgMemberTest_Failure5 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeOrgMemberTest_Failure6() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeOrgMemberTest_Failure6 Method");
//	//			userRoleDetails.setOrgId(ID);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeOrgMember(request, getAddMemberRequest());
//	//			assertEquals("This user is either incorrect or doesn't own this organization!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeOrgMemberTest_Failure6 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeOrgMemberTest_Failure7() throws Exception {
//	//		try {
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			Organization organization = getOrganization();
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeOrgMemberTest_Failure7 Method");
//	//			addMemberRequest.setOrgId(ID);
//	//			userRoleDetails.setOrgId(ID);
//	//			organization.setAdmin(list);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//	//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//	//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//	//							.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeOrgMember(request, addMemberRequest);
//	//			assertEquals(
//	//					"This user is not an Admin of the given organization and doesn't have the permission to add or remove members!",
//	//					response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeOrgMemberTest_Failure7 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeOrgMemberTest_Failure8() throws Exception {
//	//		try {
//	//			PowerMockito.mockStatic(RestUtil.class);
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			Organization organization = getOrganization();
//	//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//	//			LOGGER.debug("Inside AuthServiceImplTest:addOrgMemberTest_Failure8 Method");
//	//			list.add(VALID_USERNAME);
//	//			addMemberRequest.setOrgId(ID);
//	//			userRoleDetails.setOrgId(ID);
//	//			organization.setAdmin(list);
//	//			addMemberRequest.setRole("f5y5");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			when(userRepo.findByUsername(addMemberRequest.getUsername())).thenReturn(daoUser);
//	//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//	//			when(RestUtil.get(uri + "auth-token/api/username" + "/" + VALID_USERNAME, null, String.class))
//	//					.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeOrgMember(request, addMemberRequest);
//	//			assertEquals("The given role is not supported.", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeOrgMemberTest_Failure8 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeOrgMemberTest_Failure9() throws Exception {
//	//		try {
//	//			PowerMockito.mockStatic(RestUtil.class);
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			Organization organization = getOrganization();
//	//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//	//			LOGGER.debug("Inside AuthServiceImplTest:addOrgMemberTest_Failure8 Method");
//	//			list.add(VALID_USERNAME);
//	//			addMemberRequest.setOrgId(ID);
//	//			userRoleDetails.setOrgId(ID);
//	//			organization.setAdmin(list);
//	//			addMemberRequest.setRole("f5y5");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			when(userRepo.findByUsername(addMemberRequest.getUsername())).thenReturn(null);
//	//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//	//			when(RestUtil.get(uri + "auth-token/api/username" + "/" + VALID_USERNAME, null, String.class))
//	//					.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeOrgMember(request, addMemberRequest);
//	//			assertEquals("The provided username is either incorrect or not registered!", response.getMessage());
//	//			assertEquals(false, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeOrgMemberTest_Failure9 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeOrgMemberTest_Success1() throws Exception {
//	//		try {
//	//			PowerMockito.mockStatic(RestUtil.class);
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			Organization organization = getOrganization();
//	//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeOrgMemberTest_Success1 Method");
//	//			addMemberRequest.setOrgId(ID);
//	//			list.add(VALID_USERNAME);
//	//			addMemberRequest.setRole("ADMIN");
//	//			addMemberRequest.setUsername(VALID_USERNAME);
//	//			userRoleDetails.setOrgId(ID);
//	//			organization.setAdmin(list);
//	//			daoUser.setUsername(null);
//	//			addMemberRequest.setRole("ADMIN");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			when(userRepo.findByUsername(addMemberRequest.getUsername())).thenReturn(daoUser);
//	//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//	//			when(RestUtil.get(uri + "auth-token/api/username" + "/" + VALID_USERNAME, null, String.class))
//	//					.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeOrgMember(request, addMemberRequest);
//	//			assertEquals("Member has been removed successfully!", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeOrgMemberTest_Success1 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeOrgMemberTest_Success2() throws Exception {
//	//		try {
//	//			PowerMockito.mockStatic(RestUtil.class);
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			Organization organization = getOrganization();
//	//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeOrgMemberTest_Success2 Method");
//	//			addMemberRequest.setOrgId(ID);
//	//			list.add(VALID_USERNAME);
//	//			addMemberRequest.setUsername(VALID_USERNAME);
//	//			userRoleDetails.setOrgId(ID);
//	//			organization.setAdmin(list);
//	//			addMemberRequest.setRole("ADMIN");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			when(userRepo.findByUsername(addMemberRequest.getUsername())).thenReturn(daoUser);
//	//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//	//			when(RestUtil.get(uri + "auth-token/api/username" + "/" + VALID_USERNAME, null, String.class))
//	//					.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeOrgMember(request, addMemberRequest);
//	//			assertEquals("Member has been removed successfully!", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeOrgMemberTest_Success2 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeOrgMemberTest_Success3() throws Exception {
//	//		try {
//	//			PowerMockito.mockStatic(RestUtil.class);
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			Organization organization = getOrganization();
//	//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeOrgMemberTest_Success3 Method");
//	//			addMemberRequest.setOrgId(ID);
//	//			list.add(VALID_USERNAME);
//	//			list.add(VALID_PASSWORD);
//	//			addMemberRequest.setRole("MEMBER");
//	//			addMemberRequest.setUsername(VALID_USERNAME);
//	//			userRoleDetails.setOrgId(ID);
//	//			organization.setMember(list);
//	//			organization.setAdmin(list);
//	//			daoUser.setUsername(null);
//	//			addMemberRequest.setRole("ADMIN");
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			when(userRepo.findByUsername(addMemberRequest.getUsername())).thenReturn(daoUser);
//	//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//	//			when(RestUtil.get(uri + "auth-token/api/username" + "/" + VALID_USERNAME, null, String.class))
//	//					.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeOrgMember(request, addMemberRequest);
//	//			assertEquals("Member has been removed successfully!", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeOrgMemberTest_Success3 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//	//
//	//	@Test
//	//	public void removeOrgMemberTest_Success4() throws Exception {
//	//		try {
//	//			PowerMockito.mockStatic(RestUtil.class);
//	//			DaoUser daoUser = getDaoUser();
//	//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//	//			AddMemberRequest addMemberRequest = getAddMemberRequest();
//	//			Organization organization = getOrganization();
//	//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//	//			LOGGER.debug("Inside AuthServiceImplTest:removeOrgMemberTest_Success4 Method");
//	//			addMemberRequest.setOrgId(ID);
//	//			addMemberRequest.setRole("MEMBER");
//	//			addMemberRequest.setUsername(VALID_USERNAME);
//	//			userRoleDetails.setOrgId(ID);
//	//			list.add(VALID_USERNAME);
//	//			list.add(VALID_PASSWORD);
//	//			organization.setMember(list);
//	//			organization.setAdmin(list);
//	//			daoUser.setUserRole(userRoleDetails);
//	//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//	//			when(orgRepo.findByOrgId(Mockito.anyString())).thenReturn(organization);
//	//			when(userRepo.findByUsername(addMemberRequest.getUsername())).thenReturn(daoUser);
//	//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//	//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//	//			when(RestUtil.get(uri + "auth-token/api/username" + "/" + VALID_USERNAME, null, String.class))
//	//					.thenReturn(responseEntity);
//	//			BaseResponse response = authService.removeOrgMember(request, addMemberRequest);
//	//			assertEquals("Member has been removed successfully!", response.getMessage());
//	//			assertEquals(true, response.getSuccess());
//	//		} catch (UsernameNotFoundException e) {
//	//			LOGGER.error("Inside AuthServiceImplTest::removeOrgMemberTest_Success4 method : Unknown error {} ",
//	//					e.getMessage(), e);
//	//		}
//	//	}
//
//	@Test
//	public void validateAccessToken_Failure1() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthTokenResponse authTokenResponse = getAuthTokenResponse();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest:validateAccessToken_Failure1 Method");
//			authTokenResponse.setIsTokenValid(false);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_BEARER_TOKEN);
//			BaseResponse response = authService.validateAccessToken(request);
//			assertEquals("The provided token is not a JWT!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//			assertEquals(authTokenResponse, response.getPayload());
//			assertEquals("400", response.getStatusCode());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::validateAccessTokenTest_Failure1 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateAccessToken_Failure2() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthTokenResponse authTokenResponse = getAuthTokenResponse();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest:validateAccessToken_Failure2 Method");
//			authTokenResponse.setIsTokenValid(false);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//			ResponseEntity<Boolean> responseEntity = new ResponseEntity<>(false, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/validate/" + VALID_USERNAME, null, Boolean.class))
//			.thenReturn(responseEntity);
//			BaseResponse response = authService.validateAccessToken(request);
//			assertEquals("Authentication token is invalid.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//			assertEquals(authTokenResponse, response.getPayload());
//			assertEquals("401", response.getStatusCode());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::validateAccessTokenTest_Failure2 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateAccessToken_Failure3() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthTokenResponse authTokenResponse = getAuthTokenResponse();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest:validateAccessToken_Failure3 Method");
//			authTokenResponse.setIsTokenValid(false);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(null);
//			ResponseEntity<Boolean> booleanResponseEntity = new ResponseEntity<>(true, HttpStatus.OK);
//			ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/validate/" + VALID_USERNAME, null, Boolean.class))
//			.thenReturn(booleanResponseEntity);
//			when(RestUtil.get(uri + "auth-token/api/username/" + VALID_USERNAME, null, String.class))
//			.thenReturn(stringResponseEntity);
//			BaseResponse response = authService.validateAccessToken(request);
//			assertEquals("The provided user is invalid.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//			assertEquals(authTokenResponse, response.getPayload());
//			assertEquals("403", response.getStatusCode());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::validateAccessTokenTest_Failure3 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateAccessToken_Failure4() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			DaoUser daoUser = getDaoUser();
//			AuthTokenResponse authTokenResponse = getAuthTokenResponse();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest:validateAccessToken_Failure4 Method");
//			authTokenResponse.setIsTokenValid(false);
//			daoUser.setRefreshToken(null);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			ResponseEntity<Boolean> booleanResponseEntity = new ResponseEntity<>(true, HttpStatus.OK);
//			ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/validate/" + VALID_USERNAME, null, Boolean.class))
//			.thenReturn(booleanResponseEntity);
//			when(RestUtil.get(uri + "auth-token/api/username/" + VALID_USERNAME, null, String.class))
//			.thenReturn(stringResponseEntity);
//			BaseResponse response = authService.validateAccessToken(request);
//			assertEquals("Authentication token is invalid.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//			assertEquals(authTokenResponse, response.getPayload());
//			assertEquals("403", response.getStatusCode());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::validateAccessTokenTest_Failure4 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateAccessToken_Failure5() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			DaoUser daoUser = getDaoUser();
//			UserTokenDetails userTokenDetails = getUserTokenDetails();
//			AuthTokenResponse authTokenResponse = getAuthTokenResponse();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest:validateAccessToken_Failure5 Method");
//			authTokenResponse.setIsTokenValid(false);
//			daoUser.setRefreshToken(userTokenDetails);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			ResponseEntity<Boolean> booleanResponseEntity = new ResponseEntity<>(true, HttpStatus.OK);
//			ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/validate/" + VALID_USERNAME, null, Boolean.class))
//			.thenReturn(booleanResponseEntity);
//			when(RestUtil.get(uri + "auth-token/api/username/" + VALID_USERNAME, null, String.class))
//			.thenReturn(stringResponseEntity);
//			BaseResponse response = authService.validateAccessToken(request);
//			assertEquals("Authentication token is invalid.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//			assertEquals(authTokenResponse, response.getPayload());
//			assertEquals("403", response.getStatusCode());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::validateAccessTokenTest_Failure5 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateAccessToken_Failure6() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			DaoUser daoUser = getDaoUser();
//			UserTokenDetails userTokenDetails = getUserTokenDetails();
//			AuthTokenResponse authTokenResponse = getAuthTokenResponse();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest:validateAccessToken_Failure6 Method");
//			authTokenResponse.setIsTokenValid(false);
//			userTokenDetails.setEncryptedRT(ENCRYPTED_RT);
//			daoUser.setRefreshToken(userTokenDetails);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			ResponseEntity<Boolean> booleanResponseEntity = new ResponseEntity<>(true, HttpStatus.OK);
//			ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/validate/" + VALID_USERNAME, null, Boolean.class))
//			.thenReturn(booleanResponseEntity);
//			when(RestUtil.get(uri + "auth-token/api/username/" + VALID_USERNAME, null, String.class))
//			.thenReturn(stringResponseEntity);
//			BaseResponse response = authService.validateAccessToken(request);
//			assertEquals("Authentication token is invalid.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//			assertEquals(authTokenResponse, response.getPayload());
//			assertEquals("403", response.getStatusCode());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::validateAccessTokenTest_Failure6 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateAccessToken_Success() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			DaoUser daoUser = getDaoUser();
//			UserTokenDetails userTokenDetails = getUserTokenDetails();
//			AuthTokenResponse authTokenResponse = getAuthTokenResponse();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest:validateAccessToken_Success Method");
//			authTokenResponse.setIsTokenValid(true);
//			authTokenResponse.setUserId(ID);
//			daoUser.setId(ID);
//			userTokenDetails.setHashedRT(HASHED_TOKEN);
//			userTokenDetails.setEncryptedRT(ENCRYPTED_RT);
//			daoUser.setRefreshToken(userTokenDetails);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			ResponseEntity<Boolean> booleanResponseEntity = new ResponseEntity<>(true, HttpStatus.OK);
//			ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/validate/" + VALID_USERNAME, null, Boolean.class))
//			.thenReturn(booleanResponseEntity);
//			when(RestUtil.get(uri + "auth-token/api/username/" + VALID_USERNAME, null, String.class))
//			.thenReturn(stringResponseEntity);
//			BaseResponse response = authService.validateAccessToken(request);
//			assertEquals("Authentication token is valid.", response.getMessage());
//			assertEquals(true, response.getSuccess());
//			assertEquals(authTokenResponse, response.getPayload());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::validateAccessTokenTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Failure1() throws Exception {
//		try {
//			AuthRequest authRequest = getAuthRequest();
//			FetchResponse fetchResponse = getFetchResponse();
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Failure1 Method");
//			authRequest.setUsername(BLANK_USERNAME);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(request.getHeader("Authorization")).thenReturn(VALID_BEARER_TOKEN);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("Either the credentials are empty or the token sent is incorrect!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//			assertEquals("500", response.getStatusCode());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Failure1 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Failure2() throws Exception {
//		try {
//			AuthRequest authRequest = getAuthRequest();
//			FetchResponse fetchResponse = getFetchResponse();
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Failure2 Method");
//			authRequest.setUsername(BLANK_USERNAME);
//			when(request.getHeader("Authorization")).thenReturn(INVALID_BEARER_TOKEN);
//			when(userRepo.findByHashedRT(HASHED_TOKEN)).thenReturn(null);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("You have been logged out!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//			assertEquals("403", response.getStatusCode());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Failure2 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Failure3() throws Exception {
//		try {
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Failure3 Method");
//			authRequest.setUsername(VALID_USERNAME);
//			authRequest.setPassword(VALID_PASSWORD);
//			daoUser.setIsAccountActive(false);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			when(authenticationManager.authenticate(
//					new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())))
//			.thenReturn(authentication);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("This account is not verified.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//			assertEquals("401", response.getStatusCode());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Failure3 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Failure4() throws Exception {
//		try {
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Failure4 Method");
//			authRequest.setUsername(VALID_USERNAME);
//			authRequest.setPassword(VALID_PASSWORD);
//			daoUser.setIsAccountApproved(false);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			when(authenticationManager.authenticate(
//					new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())))
//			.thenReturn(authentication);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("This account has not been approved yet.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//			assertEquals("401", response.getStatusCode());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Failure4 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Failure5() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthRequest authRequest = getAuthRequest();
//			AuthResponse authResponse = getAuthResponse();
//			DaoUser daoUser = getDaoUser();
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Failure5 Method");
//			authRequest.setUsername(VALID_USERNAME);
//			authRequest.setPassword(VALID_PASSWORD);
//			authResponse.setAlbaUser(daoUser.getFirstName() + " " + daoUser.getLastName());
//			daoUser.setMailId(VALID_MAILID);
//			daoUser.setGoogleAuthDetails(getGoogleAuthDetails());
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			when(authenticationManager.authenticate(
//					new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())))
//			.thenReturn(authentication);
//			when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
//			ResponseEntity<String> stringResponseEntity = new ResponseEntity<>("otpToken", HttpStatus.OK);
//			when(RestUtil.get(
//					uri + "auth-token/api/generate-token/" + String.valueOf(OTP_TOKEN_DURATION) + "/" + VALID_MAILID,
//					null, String.class)).thenReturn(stringResponseEntity);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("The user is required to go for OTP Verification.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Failure5 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Failure6() throws Exception {
//		try {
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			SecurityQuesRequest securityQuesRequest = new SecurityQuesRequest();
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			securityQuesRequest.setIsUsingSQ(true);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Failure6 Method");
//			authRequest.setUsername(VALID_USERNAME);
//			authRequest.setPassword(VALID_PASSWORD);
//			daoUser.setSecurityQuestionDetails(getSecurityQuestionDetails());
//			securityQuesRequest.setQuestion(SECURITY_QUESTION);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			when(authenticationManager.authenticate(
//					new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())))
//			.thenReturn(authentication);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("The user is required to go for Security Question Verification.", response.getMessage());
//			assertEquals(false, response.getSuccess());
//			assertEquals(securityQuesRequest, response.getPayload());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Failure6 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Failure7() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			UserTokenDetails userTokenDetails = getUserTokenDetails();
//			authRequest.setUsername(BLANK_USERNAME);
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Failure7 Method");
//			userTokenDetails.setEncryptedRT(ENCRYPTED_RT);
//			userTokenDetails.setHashedRT(REFRESH_TOKEN);
//			daoUser.setRefreshToken(userTokenDetails);
//			when(request.getHeader("Authorization")).thenReturn(INVALID_BEARER_TOKEN);
//			when(userRepo.findByHashedRT(REFRESH_TOKEN)).thenReturn(daoUser);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			String sDate = "31/12/2020";
//			Date date = new SimpleDateFormat("dd/MM/yyyy").parse(sDate);
//			ResponseEntity<Date> responseEntity = new ResponseEntity<>(date, HttpStatus.OK);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			when(RestUtil.get(uri + "auth-token/api/expiration-date/" + REFRESH_TOKEN, null, Date.class))
//			.thenReturn(responseEntity);
//			when(RestUtil.get(uri + "auth-token/api/username/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(stringResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("You have been logged out!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//			assertEquals("403", response.getStatusCode());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Failure7 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Success1() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			UserTokenDetails userTokenDetails = getUserTokenDetails();
//			authRequest.setUsername(BLANK_USERNAME);
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Success1 Method");
//			userTokenDetails.setEncryptedRT(ENCRYPTED_RT);
//			userTokenDetails.setHashedRT(REFRESH_TOKEN);
//			daoUser.setRefreshToken(userTokenDetails);
//			when(request.getHeader("Authorization")).thenReturn(INVALID_BEARER_TOKEN);
//			when(userRepo.findByHashedRT(REFRESH_TOKEN)).thenReturn(daoUser);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			String sDate = "31/12/2021";
//			Date date = new SimpleDateFormat("dd/MM/yyyy").parse(sDate);
//			ResponseEntity<Date> responseEntity = new ResponseEntity<>(date, HttpStatus.OK);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			when(RestUtil.get(uri + "auth-token/api/expiration-date/" + REFRESH_TOKEN, null, Date.class))
//			.thenReturn(responseEntity);
//			when(RestUtil.get(uri + "auth-token/api/username/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(stringResponseEntity);
//			ResponseEntity<String> jwtResponseEntity = new ResponseEntity<>(ACCESS_TOKEN, HttpStatus.OK);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "access", null, daoUser, String.class))
//			.thenReturn(jwtResponseEntity);
//			ResponseEntity<String> hashedResponseEntity = new ResponseEntity<>(HASHED_TOKEN, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/encoded-token/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(hashedResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("Valid access token generated and returned", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Success1 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Success2() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//			UserTokenDetails userTokenDetails = getUserTokenDetails();
//			authRequest.setUsername(BLANK_USERNAME);
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Success2 Method");
//			userTokenDetails.setEncryptedRT(ENCRYPTED_RT);
//			userTokenDetails.setHashedRT(REFRESH_TOKEN);
//			daoUser.setUserRole(userRoleDetails);
//			daoUser.setRefreshToken(userTokenDetails);
//			when(request.getHeader("Authorization")).thenReturn(INVALID_BEARER_TOKEN);
//			when(userRepo.findByHashedRT(REFRESH_TOKEN)).thenReturn(daoUser);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			String sDate = "31/12/2021";
//			Date date = new SimpleDateFormat("dd/MM/yyyy").parse(sDate);
//			ResponseEntity<Date> responseEntity = new ResponseEntity<>(date, HttpStatus.OK);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			when(RestUtil.get(uri + "auth-token/api/expiration-date/" + REFRESH_TOKEN, null, Date.class))
//			.thenReturn(responseEntity);
//			when(RestUtil.get(uri + "auth-token/api/username/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(stringResponseEntity);
//			ResponseEntity<String> jwtResponseEntity = new ResponseEntity<>(ACCESS_TOKEN, HttpStatus.OK);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "access", null, daoUser, String.class))
//			.thenReturn(jwtResponseEntity);
//			ResponseEntity<String> hashedResponseEntity = new ResponseEntity<>(HASHED_TOKEN, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/encoded-token/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(hashedResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("Valid access token generated and returned", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Success2 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Success3() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//			UserTokenDetails userTokenDetails = getUserTokenDetails();
//			Organization organization = getOrganization();
//			authRequest.setUsername(BLANK_USERNAME);
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Success3 Method");
//			userTokenDetails.setEncryptedRT(ENCRYPTED_RT);
//			userTokenDetails.setHashedRT(REFRESH_TOKEN);
//			userRoleDetails.setOrgId(ID);
//			list.add(VALID_USERNAME);
//			//			organization.setAdmin(list);
//			daoUser.setUserRole(userRoleDetails);
//			daoUser.setRefreshToken(userTokenDetails);
//			//			when(orgRepo.findByOrgId(ID)).thenReturn(organization);
//			when(request.getHeader("Authorization")).thenReturn(INVALID_BEARER_TOKEN);
//			when(userRepo.findByHashedRT(REFRESH_TOKEN)).thenReturn(daoUser);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			String sDate = "31/12/2021";
//			Date date = new SimpleDateFormat("dd/MM/yyyy").parse(sDate);
//			ResponseEntity<Date> responseEntity = new ResponseEntity<>(date, HttpStatus.OK);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			when(RestUtil.get(uri + "auth-token/api/expiration-date/" + REFRESH_TOKEN, null, Date.class))
//			.thenReturn(responseEntity);
//			when(RestUtil.get(uri + "auth-token/api/username/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(stringResponseEntity);
//			ResponseEntity<String> jwtResponseEntity = new ResponseEntity<>(ACCESS_TOKEN, HttpStatus.OK);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "access", null, daoUser, String.class))
//			.thenReturn(jwtResponseEntity);
//			ResponseEntity<String> hashedResponseEntity = new ResponseEntity<>(HASHED_TOKEN, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/encoded-token/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(hashedResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("Valid access token generated and returned", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Success3 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Success4() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//			UserTokenDetails userTokenDetails = getUserTokenDetails();
//			Organization organization = getOrganization();
//			authRequest.setUsername(BLANK_USERNAME);
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Success4 Method");
//			userTokenDetails.setEncryptedRT(ENCRYPTED_RT);
//			userTokenDetails.setHashedRT(REFRESH_TOKEN);
//			userRoleDetails.setOrgId(ID);
//			list.add(VALID_USERNAME);
//			userRoleDetails.setProduct(productRoleDetailsList);
//			//			organization.setAdmin(list);
//			daoUser.setUserRole(userRoleDetails);
//			daoUser.setRefreshToken(userTokenDetails);
//			//			when(orgRepo.findByOrgId(ID)).thenReturn(organization);
//			when(request.getHeader("Authorization")).thenReturn(INVALID_BEARER_TOKEN);
//			when(userRepo.findByHashedRT(REFRESH_TOKEN)).thenReturn(daoUser);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			String sDate = "31/12/2021";
//			Date date = new SimpleDateFormat("dd/MM/yyyy").parse(sDate);
//			ResponseEntity<Date> responseEntity = new ResponseEntity<>(date, HttpStatus.OK);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			when(RestUtil.get(uri + "auth-token/api/expiration-date/" + REFRESH_TOKEN, null, Date.class))
//			.thenReturn(responseEntity);
//			when(RestUtil.get(uri + "auth-token/api/username/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(stringResponseEntity);
//			ResponseEntity<String> jwtResponseEntity = new ResponseEntity<>(ACCESS_TOKEN, HttpStatus.OK);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "access", null, daoUser, String.class))
//			.thenReturn(jwtResponseEntity);
//			ResponseEntity<String> hashedResponseEntity = new ResponseEntity<>(HASHED_TOKEN, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/encoded-token/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(hashedResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("Valid access token generated and returned", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Success4 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Success5() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//			UserTokenDetails userTokenDetails = getUserTokenDetails();
//			Organization organization = getOrganization();
//			authRequest.setUsername(BLANK_USERNAME);
//			List<String> list1 = new ArrayList();
//			list1.add("rtcytuvy");
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Success5 Method");
//			userTokenDetails.setEncryptedRT(ENCRYPTED_RT);
//			userTokenDetails.setHashedRT(REFRESH_TOKEN);
//			userRoleDetails.setOrgId(ID);
//			list.add(VALID_USERNAME);
//			//			organization.setAdmin(list1);
//			//			organization.setMember(list);
//			daoUser.setUserRole(userRoleDetails);
//			daoUser.setRefreshToken(userTokenDetails);
//			//			when(orgRepo.findByOrgId(ID)).thenReturn(organization);
//			when(request.getHeader("Authorization")).thenReturn(INVALID_BEARER_TOKEN);
//			when(userRepo.findByHashedRT(REFRESH_TOKEN)).thenReturn(daoUser);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			String sDate = "31/12/2021";
//			Date date = new SimpleDateFormat("dd/MM/yyyy").parse(sDate);
//			ResponseEntity<Date> responseEntity = new ResponseEntity<>(date, HttpStatus.OK);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			when(RestUtil.get(uri + "auth-token/api/expiration-date/" + REFRESH_TOKEN, null, Date.class))
//			.thenReturn(responseEntity);
//			when(RestUtil.get(uri + "auth-token/api/username/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(stringResponseEntity);
//			ResponseEntity<String> jwtResponseEntity = new ResponseEntity<>(ACCESS_TOKEN, HttpStatus.OK);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "access", null, daoUser, String.class))
//			.thenReturn(jwtResponseEntity);
//			ResponseEntity<String> hashedResponseEntity = new ResponseEntity<>(HASHED_TOKEN, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/encoded-token/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(hashedResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("Valid access token generated and returned", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Success5 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Success6() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//			UserTokenDetails userTokenDetails = getUserTokenDetails();
//			Organization organization = getOrganization();
//			authRequest.setUsername(BLANK_USERNAME);
//			List<String> list1 = new ArrayList();
//			list1.add("rtcytuvy");
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Success6 Method");
//			userTokenDetails.setEncryptedRT(ENCRYPTED_RT);
//			userTokenDetails.setHashedRT(REFRESH_TOKEN);
//			userRoleDetails.setOrgId(ID);
//			list.add(VALID_USERNAME);
//			userRoleDetails.setProduct(productRoleDetailsList);
//			//			organization.setAdmin(list1);
//			//			organization.setMember(list);
//			daoUser.setUserRole(userRoleDetails);
//			daoUser.setRefreshToken(userTokenDetails);
//			//			when(orgRepo.findByOrgId(ID)).thenReturn(organization);
//			when(request.getHeader("Authorization")).thenReturn(INVALID_BEARER_TOKEN);
//			when(userRepo.findByHashedRT(REFRESH_TOKEN)).thenReturn(daoUser);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			String sDate = "31/12/2021";
//			Date date = new SimpleDateFormat("dd/MM/yyyy").parse(sDate);
//			ResponseEntity<Date> responseEntity = new ResponseEntity<>(date, HttpStatus.OK);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			when(RestUtil.get(uri + "auth-token/api/expiration-date/" + REFRESH_TOKEN, null, Date.class))
//			.thenReturn(responseEntity);
//			when(RestUtil.get(uri + "auth-token/api/username/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(stringResponseEntity);
//			ResponseEntity<String> jwtResponseEntity = new ResponseEntity<>(ACCESS_TOKEN, HttpStatus.OK);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "access", null, daoUser, String.class))
//			.thenReturn(jwtResponseEntity);
//			ResponseEntity<String> hashedResponseEntity = new ResponseEntity<>(HASHED_TOKEN, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/encoded-token/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(hashedResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("Valid access token generated and returned", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Success6 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Success7() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//			SecurityQuestionDetails securityQuestionDetails = getSecurityQuestionDetails();
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Success7 Method");
//			authRequest.setUsername(VALID_USERNAME);
//			authRequest.setPassword(VALID_PASSWORD);
//			securityQuestionDetails.setQuestion(null);
//			daoUser.setUserRole(userRoleDetails);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			when(authenticationManager.authenticate(
//					new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())))
//			.thenReturn(authentication);
//			ResponseEntity<String> refreshResponseEntity = new ResponseEntity<>(REFRESH_TOKEN, HttpStatus.OK);
//			ResponseEntity<String> jwtResponseEntity = new ResponseEntity<>(ACCESS_TOKEN, HttpStatus.OK);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "access", null, daoUser, String.class))
//			.thenReturn(jwtResponseEntity);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "refresh", null, daoUser, String.class))
//			.thenReturn(refreshResponseEntity);
//			ResponseEntity<String> hashedResponseEntity = new ResponseEntity<>(HASHED_TOKEN, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/encoded-token/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(hashedResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("Valid access token generated and returned.", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Success7 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Success8() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//			SecurityQuestionDetails securityQuestionDetails = getSecurityQuestionDetails();
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Success8 Method");
//			authRequest.setUsername(VALID_USERNAME);
//			authRequest.setPassword(VALID_PASSWORD);
//			securityQuestionDetails.setQuestion(null);
//			daoUser.setUserRole(userRoleDetails);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			when(authenticationManager.authenticate(
//					new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())))
//			.thenReturn(authentication);
//			ResponseEntity<String> refreshResponseEntity = new ResponseEntity<>(REFRESH_TOKEN, HttpStatus.OK);
//			ResponseEntity<String> jwtResponseEntity = new ResponseEntity<>(ACCESS_TOKEN, HttpStatus.OK);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "access", null, daoUser, String.class))
//			.thenReturn(jwtResponseEntity);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "refresh", null, daoUser, String.class))
//			.thenReturn(refreshResponseEntity);
//			ResponseEntity<String> hashedResponseEntity = new ResponseEntity<>(HASHED_TOKEN, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/encoded-token/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(hashedResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("Valid access token generated and returned.", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Success8 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Success9() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			Organization organization = getOrganization();
//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//			SecurityQuestionDetails securityQuestionDetails = getSecurityQuestionDetails();
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Success9 Method");
//			authRequest.setUsername(VALID_USERNAME);
//			authRequest.setPassword(VALID_PASSWORD);
//			securityQuestionDetails.setQuestion(null);
//			list.add(VALID_USERNAME);
//			//			organization.setAdmin(list);
//			userRoleDetails.setOrgId(ID);
//			daoUser.setUserRole(userRoleDetails);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			//			when(orgRepo.findByOrgId(ID)).thenReturn(organization);
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			when(authenticationManager.authenticate(
//					new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())))
//			.thenReturn(authentication);
//			ResponseEntity<String> refreshResponseEntity = new ResponseEntity<>(REFRESH_TOKEN, HttpStatus.OK);
//			ResponseEntity<String> jwtResponseEntity = new ResponseEntity<>(ACCESS_TOKEN, HttpStatus.OK);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "access", null, daoUser, String.class))
//			.thenReturn(jwtResponseEntity);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "refresh", null, daoUser, String.class))
//			.thenReturn(refreshResponseEntity);
//			ResponseEntity<String> hashedResponseEntity = new ResponseEntity<>(HASHED_TOKEN, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/encoded-token/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(hashedResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("Valid access token generated and returned.", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Success9 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Success10() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			Organization organization = getOrganization();
//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//			SecurityQuestionDetails securityQuestionDetails = getSecurityQuestionDetails();
//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Success10 Method");
//			authRequest.setUsername(VALID_USERNAME);
//			authRequest.setPassword(VALID_PASSWORD);
//			securityQuestionDetails.setQuestion(null);
//			list.add(VALID_USERNAME);
//			userRoleDetails.setOrgId(ID);
//			//			organization.setAdmin(list);
//			userRoleDetails.setProduct(productRoleDetailsList);
//			daoUser.setUserRole(userRoleDetails);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			//			when(orgRepo.findByOrgId(ID)).thenReturn(organization);
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			when(authenticationManager.authenticate(
//					new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())))
//			.thenReturn(authentication);
//			ResponseEntity<String> refreshResponseEntity = new ResponseEntity<>(REFRESH_TOKEN, HttpStatus.OK);
//			ResponseEntity<String> jwtResponseEntity = new ResponseEntity<>(ACCESS_TOKEN, HttpStatus.OK);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "access", null, daoUser, String.class))
//			.thenReturn(jwtResponseEntity);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "refresh", null, daoUser, String.class))
//			.thenReturn(refreshResponseEntity);
//			ResponseEntity<String> hashedResponseEntity = new ResponseEntity<>(HASHED_TOKEN, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/encoded-token/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(hashedResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("Valid access token generated and returned.", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Success10 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Success11() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			Organization organization = getOrganization();
//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//			SecurityQuestionDetails securityQuestionDetails = getSecurityQuestionDetails();
//			List<String> list1 = new ArrayList();
//			list1.add("rtcytuvy");
//			list.add(VALID_USERNAME);
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Success11 Method");
//			authRequest.setUsername(VALID_USERNAME);
//			authRequest.setPassword(VALID_PASSWORD);
//			securityQuestionDetails.setQuestion(null);
//			list.add(VALID_USERNAME);
//			//			organization.setAdmin(list1);
//			//			organization.setMember(list);
//			userRoleDetails.setOrgId(ID);
//			daoUser.setUserRole(userRoleDetails);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			//			when(orgRepo.findByOrgId(ID)).thenReturn(organization);
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			when(authenticationManager.authenticate(
//					new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())))
//			.thenReturn(authentication);
//			ResponseEntity<String> refreshResponseEntity = new ResponseEntity<>(REFRESH_TOKEN, HttpStatus.OK);
//			ResponseEntity<String> jwtResponseEntity = new ResponseEntity<>(ACCESS_TOKEN, HttpStatus.OK);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "access", null, daoUser, String.class))
//			.thenReturn(jwtResponseEntity);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "refresh", null, daoUser, String.class))
//			.thenReturn(refreshResponseEntity);
//			ResponseEntity<String> hashedResponseEntity = new ResponseEntity<>(HASHED_TOKEN, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/encoded-token/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(hashedResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("Valid access token generated and returned.", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Success11 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void AuthenticateTest_Success12() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			AuthRequest authRequest = getAuthRequest();
//			DaoUser daoUser = getDaoUser();
//			RiskResponse riskResponse = getRiskResponse();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			Organization organization = getOrganization();
//			UserRoleDetails userRoleDetails = getUserRoleDetails();
//			SecurityQuestionDetails securityQuestionDetails = getSecurityQuestionDetails();
//			List<ProductRoleDetails> productRoleDetailsList = new ArrayList();
//			List<String> list1 = new ArrayList();
//			list1.add("rtcytuvy");
//			LOGGER.debug("Inside AuthServiceImplTest::AuthenticateTest_Success12 Method");
//			authRequest.setUsername(VALID_USERNAME);
//			authRequest.setPassword(VALID_PASSWORD);
//			securityQuestionDetails.setQuestion(null);
//			userRoleDetails.setOrgId(ID);
//			list.add(VALID_USERNAME);
//			//			organization.setAdmin(list1);
//			//			organization.setMember(list);
//			userRoleDetails.setProduct(productRoleDetailsList);
//			daoUser.setUserRole(userRoleDetails);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			//			when(orgRepo.findByOrgId(ID)).thenReturn(organization);
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			when(authenticationManager.authenticate(
//					new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())))
//			.thenReturn(authentication);
//			ResponseEntity<String> refreshResponseEntity = new ResponseEntity<>(REFRESH_TOKEN, HttpStatus.OK);
//			ResponseEntity<String> jwtResponseEntity = new ResponseEntity<>(ACCESS_TOKEN, HttpStatus.OK);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			ResponseEntity<RiskResponse> riskResponseEntity = new ResponseEntity<>(riskResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(webClientUtil.post(uri + "rba/api/risk-score" + "/" + VALID_USERNAME, null, fetchResponse,
//					RiskResponse.class)).thenReturn(riskResponseEntity);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "access", null, daoUser, String.class))
//			.thenReturn(jwtResponseEntity);
//			when(RestUtil.post(uri + "auth-token/api/generate-token/" + "refresh", null, daoUser, String.class))
//			.thenReturn(refreshResponseEntity);
//			ResponseEntity<String> hashedResponseEntity = new ResponseEntity<>(HASHED_TOKEN, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/encoded-token/" + REFRESH_TOKEN, null, String.class))
//			.thenReturn(hashedResponseEntity);
//			BaseResponse response = authService.authenticate(request, authRequest);
//			assertEquals("Valid access token generated and returned.", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::AuthenticateTest_Success12 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveTest_Failure1() throws Exception {
//		try {
//			RegistrationUser registrationUser = getRegistrationUser();
//			DaoUser daoUser = getDaoUser();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			LOGGER.debug("Inside AuthServiceImplTest::saveTest_Failure1 Method");
//			registrationUser.setUsername(VALID_USERNAME);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			BaseResponse response = authService.save(registrationUser, request);
//			assertEquals("Given user password is not valid!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::saveTest_Failure1 method : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveTest_Failure2() throws Exception {
//		try {
//			RegistrationUser registrationUser = getRegistrationUser();
//			DaoUser daoUser = getDaoUser();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			LOGGER.debug("Inside AuthServiceImplTest::saveTest_Failure2 Method");
//			registrationUser.setUsername(INVALID_USERNAME);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			BaseResponse response = authService.save(registrationUser, request);
//			assertEquals("Given username is not valid!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::saveTest_Failure2 method : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveTest_Failure3() throws Exception {
//		try {
//			RegistrationUser registrationUser = getRegistrationUser();
//			DaoUser daoUser = getDaoUser();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			LOGGER.debug("Inside AuthServiceImplTest::saveTest_Failure3 Method");
//			registrationUser.setUsername(VALID_MAILID);
//			registrationUser.setMailId(INVALID_MAILID);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			BaseResponse response = authService.save(registrationUser, request);
//			assertEquals("You cannot use a different email as username!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::saveTest_Failure3 method : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveTest_Failure4() throws Exception {
//		try {
//			RegistrationUser registrationUser = getRegistrationUser();
//			DaoUser daoUser = getDaoUser();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			LOGGER.debug("Inside AuthServiceImplTest::saveTest_Failure4 Method");
//			registrationUser.setUsername(VALID_USERNAME);
//			registrationUser.setPassword(VALID_PASSWORD);
//			registrationUser.setConfirmedPassword(INVALID_PASSWORD);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			BaseResponse response = authService.save(registrationUser, request);
//			assertEquals("Password fields do not match!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::saveTest_Failure4 method : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveTest_Failure5() throws Exception {
//		try {
//			RegistrationUser registrationUser = getRegistrationUser();
//			DaoUser daoUser = getDaoUser();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			LOGGER.debug("Inside AuthServiceImplTest::saveTest_Failure5 Method");
//			registrationUser.setUsername(VALID_USERNAME);
//			registrationUser.setPassword(VALID_PASSWORD);
//			registrationUser.setConfirmedPassword(VALID_PASSWORD);
//			registrationUser.setMailId(INVALID_MAILID);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			BaseResponse response = authService.save(registrationUser, request);
//			assertEquals("Given user email is not valid!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::saveTest_Failure5 method : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveTest_Failure6() throws Exception {
//		try {
//			RegistrationUser registrationUser = getRegistrationUser();
//			DaoUser daoUser = getDaoUser();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			LOGGER.debug("Inside AuthServiceImplTest::saveTest_Failure6 Method");
//			registrationUser.setUsername(VALID_USERNAME);
//			registrationUser.setPassword(VALID_PASSWORD);
//			registrationUser.setConfirmedPassword(VALID_PASSWORD);
//			registrationUser.setMailId(VALID_MAILID);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(getDaoUser());
//			BaseResponse response = authService.save(registrationUser, request);
//			assertEquals("A user already exists with the given identities!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::saveTest_Failure6 method : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveTest_Failure7() throws Exception {
//		try {
//			RegistrationUser registrationUser = getRegistrationUser();
//			DaoUser daoUser = getDaoUser();
//			daoUser.setMailId(VALID_MAILID);
//			FetchResponse fetchResponse = getFetchResponse();
//			LOGGER.debug("Inside AuthServiceImplTest::saveTest_Failure7 Method");
//			registrationUser.setUsername(VALID_USERNAME);
//			registrationUser.setPassword(VALID_PASSWORD);
//			registrationUser.setConfirmedPassword(VALID_PASSWORD);
//			registrationUser.setMailId(VALID_MAILID);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(userRepo.findByMailId(Mockito.anyString())).thenReturn(getDaoUser());
//			BaseResponse response = authService.save(registrationUser, request);
//			assertEquals("A user already exists with the given identities!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::saveTest_Failure7 method : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveTest_Success1() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			PowerMockito.mockStatic(Session.class);
//			RegistrationUser registrationUser = getRegistrationUser();
//			DaoUser daoUser = getDaoUser();
//			daoUser.setMailId(VALID_MAILID);
//			BaseResponse baseResponse = getBaseResponse();
//			FetchResponse fetchResponse = getFetchResponse();
//			List<SecurityQuestions> securityQuestionsList = new ArrayList();
//			securityQuestionsList.add(getSecurityQuestions());
//			LOGGER.debug("Inside AuthServiceImplTest::saveTest_Success1 Method");
//			registrationUser.setUsername(VALID_USERNAME);
//			registrationUser.setPassword(VALID_PASSWORD);
//			registrationUser.setConfirmedPassword(VALID_PASSWORD);
//			registrationUser.setMailId(VALID_MAILID);
//			registrationUser.setIsUsing2FA(IS_USING_2FA);
//			registrationUser.setSecret(SECRET);
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(null);
//			when(userRepo.findByMailId(Mockito.anyString())).thenReturn(null);
//			when(securityQuestionsRepo.findAll()).thenReturn(securityQuestionsList);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("dummyString", HttpStatus.OK);
//			ResponseEntity<BaseResponse> baseResponseEntity = new ResponseEntity<>(baseResponse, HttpStatus.OK);
//			when(webClientUtil.post(uri + "rba/api/save-auth-history" + "/" + VALID_USERNAME, null, fetchResponse,
//					BaseResponse.class)).thenReturn(baseResponseEntity);
//			when(RestUtil.get(uri + "auth-token/api/generate-token/" + String.valueOf(USER_VERIFICATION_TOKEN_DURATION)
//			+ "/" + VALID_MAILID, null, String.class)).thenReturn(responseEntity);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
//			when(Session.getInstance(Mockito.any(), Mockito.any())).thenReturn(session);
//			when(session.getTransport()).thenReturn(transport);
//			BaseResponse response = authService.save(registrationUser, request);
//			assertEquals("User added and MFA details saved!", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::saveTest_Success1 method : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveTest_Success2() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			PowerMockito.mockStatic(Session.class);
//			RegistrationUser registrationUser = getRegistrationUser();
//			DaoUser daoUser = getDaoUser();
//			daoUser.setMailId(VALID_MAILID);
//			BaseResponse baseResponse = getBaseResponse();
//			FetchResponse fetchResponse = getFetchResponse();
//			List<SecurityQuestions> securityQuestionsList = new ArrayList();
//			securityQuestionsList.add(getSecurityQuestions());
//			LOGGER.debug("Inside AuthServiceImplTest::saveTest_Success2 Method");
//			registrationUser.setUsername(VALID_USERNAME);
//			registrationUser.setPassword(VALID_PASSWORD);
//			registrationUser.setConfirmedPassword(VALID_PASSWORD);
//			registrationUser.setMailId(VALID_MAILID);
//			registrationUser.setIsUsing2FA(IS_USING_2FA);
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(null);
//			when(userRepo.findByMailId(Mockito.anyString())).thenReturn(null);
//			when(securityQuestionsRepo.findAll()).thenReturn(securityQuestionsList);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("dummyString", HttpStatus.OK);
//			ResponseEntity<BaseResponse> baseResponseEntity = new ResponseEntity<>(baseResponse, HttpStatus.OK);
//			when(webClientUtil.post(uri + "rba/api/save-auth-history" + "/" + VALID_USERNAME, null, fetchResponse,
//					BaseResponse.class)).thenReturn(baseResponseEntity);
//			when(RestUtil.get(uri + "auth-token/api/generate-token/" + String.valueOf(USER_VERIFICATION_TOKEN_DURATION)
//			+ "/" + VALID_MAILID, null, String.class)).thenReturn(responseEntity);
//			ResponseEntity<FetchResponse> fetchResponseEntity = new ResponseEntity<>(fetchResponse, HttpStatus.OK);
//			when(webClientUtil.get(uri + "rba/api/request-details", null, FetchResponse.class))
//			.thenReturn(fetchResponseEntity);
//			when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
//			when(Session.getInstance(Mockito.any(), Mockito.any())).thenReturn(session);
//			when(session.getTransport()).thenReturn(transport);
//			BaseResponse response = authService.save(registrationUser, request);
//			assertEquals("User added!", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::saveTest_Success2 method : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getSecurityQuestionsTest_Failure() throws Exception {
//		try {
//			SecurityQuestions securityQuestions = getSecurityQuestions();
//			List<SecurityQuestions> securityQuestionsList = new ArrayList();
//			LOGGER.debug("Inside AuthServiceImplTest:getSecurityQuestionsTest_Success Method");
//			securityQuestionsList.add(securityQuestions);
//			securityQuestions.setQuestions(null);
//			when(securityQuestionsRepo.findAll()).thenReturn(securityQuestionsList);
//			BaseResponse response = authService.getSecurityQuestions();
//			assertEquals(false, response.getSuccess());
//			assertEquals("No question found!", response.getMessage());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::getSecurityQuestionsTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveSecurityQuestionTest_Failure() throws Exception {
//		try {
//			DaoUser daoUser = getDaoUser();
//			SecurityQuesRequest securityQuesRequest = getSecurityQuesRequest();
//			SecurityQuestions securityQuestions = getSecurityQuestions();
//			List<SecurityQuestions> securityQuestionsList = new ArrayList();
//			LOGGER.debug("Inside AuthServiceImplTest:saveSecurityQuestionTest_Failure Method");
//			List<ServiceInstance> serviceInstanceList = new ArrayList();
//			serviceInstanceList.add(serviceInstance);
//			securityQuestionsList.add(securityQuestions);
//			when(securityQuestionsRepo.findAll()).thenReturn(securityQuestionsList);
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//			when(discoveryClient.getInstances(Mockito.anyString())).thenReturn(serviceInstanceList);
//			when(serviceInstance.getUri()).thenReturn(uri);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//
//			BaseResponse response = authService.saveSecurityQuestion(request, securityQuesRequest);
//			assertEquals("This question is not valid!", response.getMessage());
//			assertEquals(false, response.getSuccess());
//
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::saveSecurityQuestionTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveSecurityQuestionTest_Success() throws Exception {
//		try {
//			DaoUser daoUser = getDaoUser();
//			SecurityQuesRequest securityQuesRequest = getSecurityQuesRequest();
//			SecurityQuestions securityQuestions = getSecurityQuestions();
//			List<SecurityQuestions> securityQuestionsList = new ArrayList();
//			LOGGER.debug("Inside AuthServiceImplTest:saveSecurityQuestionTest_Success Method");
//			List<ServiceInstance> serviceInstanceList = new ArrayList();
//			serviceInstanceList.add(serviceInstance);
//			securityQuesRequest.setQuestion(SECURITY_ANSWER);
//			securityQuestionsList.add(securityQuestions);
//			when(securityQuestionsRepo.findAll()).thenReturn(securityQuestionsList);
//			when(userRepo.findByUsername(Mockito.anyString())).thenReturn(daoUser);
//			when(discoveryClient.getInstances(Mockito.anyString())).thenReturn(serviceInstanceList);
//			when(serviceInstance.getUri()).thenReturn(uri);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>("hello", HttpStatus.OK);
//			when(restTemplate.exchange(ArgumentMatchers.anyString(), ArgumentMatchers.any(HttpMethod.class),
//					ArgumentMatchers.<HttpEntity<?>>any(), ArgumentMatchers.<Class<String>>any()))
//			.thenReturn(responseEntity);
//			BaseResponse response = authService.saveSecurityQuestion(request, securityQuesRequest);
//			assertEquals("Successfully added security question details.", response.getMessage());
//			assertEquals(true, response.getSuccess());
//
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::saveSecurityQuestionTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkForSQTest_Success() throws Exception {
//		try {
//			SecurityQuestionDetails SecurityQuestionDetails = getSecurityQuestionDetails();
//			SecurityQuestions securityQuestions = getSecurityQuestions();
//			SecurityQuestions securityQuestions1 = getSecurityQuestions();
//			SecurityQuestions securityQuestions2 = getSecurityQuestions();
//			SecurityQuestions securityQuestions3 = getSecurityQuestions();
//			SecurityQuestions securityQuestions4 = getSecurityQuestions();
//			List<SecurityQuestions> securityQuestionsList = new ArrayList();
//			LOGGER.debug("Inside AuthServiceImplTest:checkForSQTest_Success Method");
//			securityQuestionsList.add(securityQuestions);
//			securityQuestionsList.add(securityQuestions1);
//			securityQuestionsList.add(securityQuestions2);
//			securityQuestionsList.add(securityQuestions3);
//			securityQuestionsList.add(securityQuestions4);
//			when(securityQuestionsRepo.findAll()).thenReturn(securityQuestionsList);
//			BaseResponse response = authService.checkForSQ(VALID_USERNAME);
//			response.setSuccess(true);
//			response.setMessage("Security Questions returned.");
//			assertEquals(true, response.getSuccess());
//			assertEquals("Security Questions returned.", response.getMessage());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkForSQ_Sucsess method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkForSQTest_Failure() throws Exception {
//		try {
//			SecurityQuestions securityQuestions = getSecurityQuestions();
//			List<SecurityQuestions> securityQuestionsList = new ArrayList();
//			LOGGER.debug("Inside AuthServiceImplTest:getSecurityQuestionsTest_Success Method");
//			securityQuestionsList.add(securityQuestions);
//			securityQuestions.setQuestions(null);
//			when(securityQuestionsRepo.findAll()).thenReturn(securityQuestionsList);
//			BaseResponse response = authService.checkForSQ(VALID_USERNAME);
//			assertEquals(false, response.getSuccess());
//			assertEquals("No question found!", response.getMessage());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::getSecurityQuestionsTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getSecurityQuestionsTest_Success() throws Exception {
//		try {
//			SecurityQuestions securityQuestions = getSecurityQuestions();
//			SecurityQuestions securityQuestions1 = getSecurityQuestions();
//			SecurityQuestions securityQuestions2 = getSecurityQuestions();
//			SecurityQuestions securityQuestions3 = getSecurityQuestions();
//			SecurityQuestions securityQuestions4 = getSecurityQuestions();
//			List<SecurityQuestions> securityQuestionsList = new ArrayList();
//			LOGGER.debug("Inside AuthServiceImplTest:getSecurityQuestionsTest_Success Method");
//			securityQuestionsList.add(securityQuestions);
//			securityQuestionsList.add(securityQuestions1);
//			securityQuestionsList.add(securityQuestions2);
//			securityQuestionsList.add(securityQuestions3);
//			securityQuestionsList.add(securityQuestions4);
//			when(securityQuestionsRepo.findAll()).thenReturn(securityQuestionsList);
//			BaseResponse response = authService.getSecurityQuestions();
//			assertEquals(true, response.getSuccess());
//			assertEquals("Security Questions returned.", response.getMessage());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::getSecurityQuestionsTest_Sucsess method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkSQTest_Success() {
//		try {
//			String Header = "Bearer Hello";
//			DaoUser daouser = new DaoUser();
//			java.util.List<ServiceInstance> serviceInstanceList = new ArrayList<>();
//			serviceInstanceList.add(serviceInstance);
//			String token = request.getHeader(Header);
//			when(discoveryClient.getInstances(Mockito.anyString())).thenReturn(serviceInstanceList);
//			when(serviceInstance.getUri()).thenReturn(uri);
//			ResponseEntity<String> usernameResponse = RestUtil.get(uri + token, null, String.class);
//
//			String username = usernameResponse.getBody();
//			daouser.setUsername(username);
//			when(userRepo.findByUsername(username)).thenReturn(daouser);
//			SecurityQuestionDetails SecurityQuestionDetails = getSecurityQuestionDetails();
//			daouser.setSecurityQuestionDetails(SecurityQuestionDetails);
//			Boolean response = authService.checkSQ(request);
//			System.out.println(response);
//			assertEquals(daouser.getSecurityQuestionDetails().getIsUsingSQ(), response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkMfaTest_Success method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void checkSQTest_Failure() {
//		try {
//			Boolean response = authService.checkSQ(null);
//			assertEquals(false, response);
//		} catch (Exception e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkSQTest_Failure method : Unknown error {} ", e.getMessage(),
//					e);
//		}
//	}
//
//	@Test
//	public void checkSecurityQuestionTest_Failure1() throws Exception
//	{
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			SecurityQuesRequest securityQuesRequest = getSecurityQuesRequest();
//			DaoUser daoUser = getDaoUser();
//			SecurityQuestionDetails securityQuestionDetails = getSecurityQuestionDetails();
//			daoUser.setSecurityQuestionDetails(securityQuestionDetails);
//			LOGGER.debug("Inside AuthServiceImplTest:checkSecurityQuestionTest_Success1 Method");
//			daoUser.getSecurityQuestionDetails().setAnswer(HASHED_ANSWER);
//			securityQuesRequest.setAnswer(SECURITY_ANSWER);
//			securityQuesRequest.setQuestion(SECURITY_QUESTION);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			BaseResponse response = authService.checkSecurityQuestion(VALID_USERNAME, getSecurityQuesRequest());
//			assertEquals(false, response.getSuccess());
//			assertEquals("Answer is null or invalid", response.getMessage());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkSecurityQuestionTest_Success1 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkSecurityQuestionTest_Failure2() throws Exception {
//		try {
//			DaoUser daoUser = getDaoUser();
//			SecurityQuestionDetails securityQuestionDetails = getSecurityQuestionDetails();
//			LOGGER.debug("Inside AuthServiceImplTest:checkSecurityQuestionTest_Failure1 Method");
//			securityQuestionDetails.setAnswer(SECURITY_ANSWER);
//			daoUser.setSecurityQuestionDetails(securityQuestionDetails);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(getDaoUser());
//			BaseResponse response = authService.checkSecurityQuestion(VALID_USERNAME,getSecurityQuesRequest());
//			assertEquals(false, response.getSuccess());
//			assertEquals("Answer is null or invalid", response.getMessage());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkSecurityQuestionTest_Failure1 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkPasswordTest_Failure1() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest:checkPasswordTest_Failure1 Method");
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/username/" +VALID_USERNAME , null, String.class))
//			.thenReturn(responseEntity);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(null);
//			BaseResponse response = authService.checkPassword(request, VALID_PASSWORD);
//			assertEquals(false, response.getSuccess());
//			assertEquals("Error occured while comparing passwords", response.getMessage());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkPasswordTest_Failure1 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkPasswordTest_Failure2() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			DaoUser daoUser = getDaoUser();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest:checkPasswordTest_Failure2 Method");
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/username/" +VALID_USERNAME , null, String.class))
//			.thenReturn(responseEntity);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			BaseResponse response = authService.checkPassword(request, INVALID_PASSWORD);
//			assertEquals(false, response.getSuccess());
//			assertEquals("Passwords don't match", response.getMessage());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkPasswordTest_Failure2 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void checkPasswordTest_Success() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			DaoUser daoUser = getDaoUser();
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest:checkPasswordTest_Success Method");
//			when(request.getHeader("Authorization")).thenReturn(ENCRYPTED_VALID_BEARER_TOKEN);
//			ResponseEntity<String> responseEntity = new ResponseEntity<>(VALID_USERNAME, HttpStatus.OK);
//			when(RestUtil.get(uri + "auth-token/api/username/" +VALID_USERNAME , null, String.class))
//			.thenReturn(responseEntity);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			BaseResponse response = authService.checkPassword(request, VALID_PASSWORD);
//			assertEquals(false, response.getSuccess());
//			assertEquals("Passwords don't match", response.getMessage());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::checkPasswordTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void securityChecksTest_Failure1() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			LOGGER.debug("Inside AuthServiceImplTest:securityChecksTest_Failure1 Method");
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(null);
//			BaseResponse response = authService.securityChecks(VALID_USERNAME);
//			assertEquals(false, response.getSuccess());
//			assertEquals("Exception Occured while validating authentication token!", response.getMessage());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::securityChecksTest_Failure1 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void securityChecksTest_Failure2() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			DaoUser daoUser =  getDaoUser();
//			LOGGER.debug("Inside AuthServiceImplTest:securityChecksTest_Failure2 Method");
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userOrgRoleRepo.findByUserId(ID)).thenReturn(null);
//			BaseResponse response = authService.securityChecks(VALID_USERNAME);
//			assertEquals(false, response.getSuccess());
//			assertEquals("There is no role assigned to this user!", response.getMessage());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::securityChecksTest_Failure2 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void securityChecksTest_Failure3() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			DaoUser daoUser =  getDaoUser();
//			daoUser.setIsAccountActive(false);
//			LOGGER.debug("Inside AuthServiceImplTest:securityChecksTest_Failure3 Method");
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userOrgRoleRepo.findByUserId(ID)).thenReturn(null);
//			BaseResponse response = authService.securityChecks(VALID_USERNAME);
//			assertEquals(false, response.getSuccess());
//			assertEquals("This account is not verified.", response.getMessage());
//			assertEquals("401", response.getStatusCode());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::securityChecksTest_Failure3 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void securityChecksTest_Failure4() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			DaoUser daoUser =  getDaoUser();
//			daoUser.setIsAccountApproved(false);
//			LOGGER.debug("Inside AuthServiceImplTest:securityChecksTest_Failure4 Method");
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userOrgRoleRepo.findByUserId(ID)).thenReturn(null);
//			BaseResponse response = authService.securityChecks(VALID_USERNAME);
//			assertEquals(false, response.getSuccess());
//			assertEquals("This account has not been approved yet.", response.getMessage());
//			assertEquals("401", response.getStatusCode());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::securityChecksTest_Failure4 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void securityChecksTest_Failure5() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			DaoUser daoUser =  getDaoUser();
//			AuthRequest authRequest = getAuthRequest();
//			AuthResponse authResponse = getAuthResponse();
//			daoUser.setGoogleAuthDetails(getGoogleAuthDetails());
//			ReflectionTestUtils.setField(authService, "encryptorPassword", "password");
//			LOGGER.debug("Inside AuthServiceImplTest:securityChecksTest_Failure5 Method");
//			daoUser.setMailId(VALID_MAILID);
//			authRequest.setUsername(VALID_USERNAME);
//			authRequest.setPassword(VALID_PASSWORD);
//			authResponse.setAlbaUser(daoUser.getFirstName() + " " + daoUser.getLastName());
//			daoUser.setMailId(VALID_MAILID);
//			daoUser.setGoogleAuthDetails(getGoogleAuthDetails());
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userRepo.findByMailId(VALID_MAILID)).thenReturn(daoUser);
//			when(authenticationManager.authenticate(
//					new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())))
//			.thenReturn(authentication);
//			when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
//			ResponseEntity<String> stringResponseEntity = new ResponseEntity<>("otpToken", HttpStatus.OK);
//			when(RestUtil.get(
//					uri + "auth-token/api/generate-token/" + String.valueOf(OTP_TOKEN_DURATION) + "/" + VALID_MAILID,
//					null, String.class)).thenReturn(stringResponseEntity);
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userOrgRoleRepo.findByUserId(ID)).thenReturn(null);
//			BaseResponse response = authService.securityChecks(VALID_USERNAME);
//			assertEquals(false, response.getSuccess());
//			assertEquals("The user is required to go for OTP Verification.", response.getMessage());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::securityChecksTest_Failure5 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void securityChecksTest_Failure6() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			DaoUser daoUser =  getDaoUser();
//			SecurityQuestionDetails securityQuestionDetails = getSecurityQuestionDetails();
//			daoUser.setSecurityQuestionDetails(securityQuestionDetails);
//			LOGGER.debug("Inside AuthServiceImplTest:securityChecksTest_Failure6 Method");
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userOrgRoleRepo.findByUserId(ID)).thenReturn(null);
//			BaseResponse response = authService.securityChecks(VALID_USERNAME);
//			assertEquals(false, response.getSuccess());
//			assertEquals("The user is required to go for Security Question Verification.", response.getMessage());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::securityChecksTest_Failure6 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void securityChecksTest_Success() throws Exception {
//		try {
//			PowerMockito.mockStatic(RestUtil.class);
//			DaoUser daoUser =  getDaoUser();
//			UserOrgRole userOrgRole = getUserOrgRole();
//			AuthResponse authResponse = getAuthResponse();
//			BaseResponse baseResponse = getBaseResponse();
//			UserIdDetails userIdDetails = getUserIdDetails();
//			LOGGER.debug("Inside AuthServiceImplTest:securityChecksTest_Success Method");
//			when(userRepo.findByUsername(VALID_USERNAME)).thenReturn(daoUser);
//			when(userOrgRoleRepo.findByUserId(ID)).thenReturn(userOrgRole);
//			doNothing().when(userRoleService).setUserIdDetails(userOrgRole, daoUser, authResponse, userIdDetails, baseResponse);
//			BaseResponse response = authService.securityChecks(VALID_USERNAME);
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside AuthServiceImplTest::securityChecksTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//}