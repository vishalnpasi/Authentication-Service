//package com.albanero.authenticationservice.service;
//
//import static org.junit.Assert.assertEquals;
//import static org.mockito.ArgumentMatchers.any;
//import static org.mockito.Mockito.when;
//
//import java.util.ArrayList;
//
//import org.junit.Before;
//import org.junit.jupiter.api.Test;
//import org.junit.runner.RunWith;
//import org.mockito.InjectMocks;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.mockito.MockitoAnnotations;
//import org.powermock.core.classloader.annotations.PrepareForTest;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.test.context.junit4.SpringRunner;
//
//import com.albanero.authservice.common.dto.AuthRequest;
//import com.albanero.authservice.common.dto.RegistrationUser;
//import com.albanero.authservice.common.dto.response.AuthResponse;
//import com.albanero.authservice.common.dto.response.BaseResponse;
//import com.albanero.authservice.common.util.JwtUtil;
//import com.albanero.authservice.model.DaoUser;
//import com.albanero.authservice.model.UserTokenDetails;
//import com.albanero.authservice.repository.UserRepository;
//import com.albanero.authservice.service.AuthService;
//
//@RunWith(SpringRunner.class)
//@PrepareForTest({ JwtUtil.class })
//public class AuthServiceTest {
//
//	private static final Logger LOGGER = LoggerFactory.getLogger(AuthServiceTest.class);
//	private static final String ACCESS_TOKEN = "token.token.token";
//	private static final String REFRESH_JWT = "refresh.refresh.refresh";
//	private static final String REFRESH_TOKEN = "refreshtoken";
//	private static final String REFRESH_TOKEN_ENC = "refreshtoken";
//	private static final String USERNAME = "test_username";
//	private static final String PASSWORD = "test_password";
//
//	@Mock
//	private UserRepository userRepo;
//
//	@Mock
//	private JwtUtil jwtUtil;
//
//	@InjectMocks
//	private AuthService authService;
//
//	@Before
//	public void setUp() throws Exception {
//		MockitoAnnotations.initMocks(this);
//	}
//
//	private UserDetails getUserDetails() {
//		AuthRequest user = new AuthRequest();
//		user.setPassword(PASSWORD);
//		user.setUsername(USERNAME);
//		return new User(user.getUsername(), user.getPassword(), new ArrayList<>());
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
//		authRequest.setUsername("");
//		authRequest.setPassword("");
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
//	private UserTokenDetails getUserTokenDetails() {
//		UserTokenDetails userTokenDetails = new UserTokenDetails();
//		userTokenDetails.setEncryptedRT(REFRESH_TOKEN);
//		userTokenDetails.setHashedRT(REFRESH_TOKEN_ENC);
//		return userTokenDetails;
//	}
//
//	private DaoUser getDaoUser() {
//		DaoUser user = new DaoUser();
//		user.setUsername(USERNAME);
//		user.setPassword(PASSWORD);
//		user.setRefreshToken(getUserTokenDetails());
//		user.setRole("ROLE_ADMIN");
//		return user;
//	}
//
//	@Test
//	public void loadUserByUsernameTest_Success() {
//		try {
//			LOGGER.debug("Inside UsersServiceImplTest::loadUserByUsernameTest_Success Method");
//			when(userRepo.findByUsername(USERNAME)).thenReturn(getDaoUser());
//			UserDetails response = authService.loadUserByUsername(Mockito.<String>any());
//			assertEquals(USERNAME, response.getUsername());
//			assertEquals(PASSWORD, response.getPassword());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside UsersServiceImplTest::loadUserByUsernameTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void loadUserByUsernameTest_Failure() {
//		try {
//			LOGGER.debug("Inside UsersServiceImplTest::loadUserByUsernameTest_Failure Method");
//			when(userRepo.findByUsername(Mockito.<String>any())).thenReturn(null);
//			UserDetails response = authService.loadUserByUsername(Mockito.<String>any());
//			assertEquals(null, response.getUsername());
//			assertEquals(null, response.getPassword());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside UsersServiceImplTest::loadUserByUsernameTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveTest_Success() throws Exception {
//		try {
//			LOGGER.debug("Inside UsersServiceImplTest::saveTest_Success Method");
//			when(userRepo.findByUsername(Mockito.<String>any())).thenReturn(getDaoUser());
//			BaseResponse response = authService.save(Mockito.<RegistrationUser>any());
//			assertEquals("User added!", response.getMessage());
//			assertEquals(true, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside UsersServiceImplTest::saveTest_Success method : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveTest_Failure() throws Exception {
//		try {
//			LOGGER.debug("Inside UsersServiceImplTest::saveTest_Failure Method");
//			when(userRepo.findByUsername(Mockito.<String>any())).thenReturn(null);
//			BaseResponse response = authService.save(Mockito.<RegistrationUser>any());
//			assertEquals(false, response.getSuccess());
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside UsersServiceImplTest::saveTest_Failure method : Unknown error {} ", e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveRefreshTokenTest_Success() {
//		try {
//			LOGGER.debug("Inside UsersServiceImplTest::saveRefreshTokenTest_Success Method");
//			when(userRepo.findByUsername(Mockito.<String>any())).thenReturn(getDaoUser());
//			String response = authService.saveRefreshToken(Mockito.<String>any(), Mockito.<String>any());
//			assertEquals(REFRESH_TOKEN_ENC, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside UsersServiceImplTest::saveRefreshTokenTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void saveRefreshTokenTest_Failure() {
//		try {
//			LOGGER.debug("Inside UsersServiceImplTest::saveRefreshTokenTest_Failure Method");
//			when(userRepo.findByUsername(Mockito.<String>any())).thenReturn(null);
//			String response = authService.saveRefreshToken(Mockito.<String>any(), Mockito.<String>any());
//			assertEquals(null, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside UsersServiceImplTest::saveRefreshTokenTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getDecodedRefreshTokenTest_Success() {
//		try {
//			LOGGER.debug("Inside UsersServiceImplTest::getDecodedRefreshTokenTest_Success Method");
//			when(userRepo.findByHashedRT(Mockito.<String>any())).thenReturn(getDaoUser());
//			String response = authService.getDecodedRefreshToken(Mockito.<String>any());
//			assertEquals(REFRESH_TOKEN, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside UsersServiceImplTest::getDecodedRefreshTokenTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void getDecodedRefreshTokenTest_Failure() {
//		try {
//			LOGGER.debug("Inside UsersServiceImplTest::getDecodedRefreshTokenTest_Failure Method");
//			when(userRepo.findByHashedRT(Mockito.<String>any())).thenReturn(null);
//			String response = authService.getDecodedRefreshToken(Mockito.<String>any());
//			assertEquals(null, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside UsersServiceImplTest::getDecodedRefreshTokenTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateRefreshTokenTest_Success() {
//		try {
//			LOGGER.debug("Inside UsersServiceImplTest::validateRefreshTokenTest_Success Method");
//			when(userRepo.findByHashedRT(Mockito.<String>any())).thenReturn(getDaoUser());
//			Boolean response = authService.validateRefreshToken(Mockito.<String>any());
//			assertEquals(true, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside UsersServiceImplTest::validateRefreshTokenTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void validateRefreshTokenTest_Failure() {
//		try {
//			LOGGER.debug("Inside UsersServiceImplTest::validateRefreshTokenTest_Failure Method");
//			when(userRepo.findByHashedRT(Mockito.<String>any())).thenReturn(null);
//			Boolean response = authService.validateRefreshToken(Mockito.<String>any());
//			assertEquals(false, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside UsersServiceImplTest::validateRefreshTokenTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void isRTPresentTest_Success() {
//		try {
//			LOGGER.debug("Inside UsersServiceImplTest::isRTPresentTest_Success Method");
//			when(userRepo.findByHashedRT(Mockito.<String>any())).thenReturn(getDaoUser());
//			Boolean response = authService.validateRefreshToken(Mockito.<String>any());
//			assertEquals(true, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside UsersServiceImplTest::isRTPresentTest_Success method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
//	@Test
//	public void isRTPresentTest_Failure() {
//		try {
//			LOGGER.debug("Inside UsersServiceImplTest::isRTPresentTest_Failure Method");
//			when(userRepo.findByHashedRT(Mockito.<String>any())).thenReturn(null);
//			Boolean response = authService.validateRefreshToken(Mockito.<String>any());
//			assertEquals(false, response);
//		} catch (UsernameNotFoundException e) {
//			LOGGER.error("Inside UsersServiceImplTest::isRTPresentTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//
////	@Test
////	public void extractJwtFromRequest_Success() {
////		try {
////			LOGGER.debug("Inside UsersServiceImplTest::extractJwtFromRequest_Success Method");
////			when(userRepo.findByHashedRT(Mockito.<String>any())).thenReturn(getDaoUser());
////			String response = authService.extractJwtFromRequest(Mockito.<HttpServletRequest>any());
////			assertEquals(true,response);
////		} catch (UsernameNotFoundException e) {
////			LOGGER.error("Inside UsersServiceImplTest::extractJwtFromRequest_Success method : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
////	
////	@Test
////	public void extractJwtFromRequest_Failure() {
////		try {
////			LOGGER.debug("Inside UsersServiceImplTest::extractJwtFromRequest_Failure Method");
////			when(userRepo.findByHashedRT(Mockito.<String>any())).thenReturn(getDaoUser());
////			Boolean response = authService.validateRefreshToken(Mockito.<String>any());
////			assertEquals(true,response);
////		} catch (UsernameNotFoundException e) {
////			LOGGER.error("Inside UsersServiceImplTest::extractJwtFromRequest_Failure method : Unknown error {} ",
////					e.getMessage(), e);
////		}
////	}
//}
