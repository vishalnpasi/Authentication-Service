//package com.albanero.authenticationservice.controller;
//
//import static org.junit.Assert.assertEquals;
//import static org.mockito.Mockito.when;
//import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
//import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
//
//import java.util.ArrayList;
//
//import jakarta.servlet.ServletContext;
//import jakarta.servlet.http.HttpServletRequest;
//
//import org.junit.Assert;
//import org.junit.Before;
//import org.junit.jupiter.api.Test;
//import org.junit.runner.RunWith;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.mockito.MockitoAnnotations;
//import org.mockito.junit.MockitoJUnitRunner;
//import org.powermock.api.mockito.PowerMockito;
//import org.powermock.core.classloader.annotations.PrepareForTest;
//import org.powermock.modules.junit4.PowerMockRunner;
//import org.powermock.modules.junit4.PowerMockRunnerDelegate;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.mock.web.MockServletContext;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.test.context.TestPropertySource;
//import org.springframework.test.context.TestPropertySources;
//import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
//import org.springframework.test.context.junit4.SpringRunner;
//import org.springframework.test.web.servlet.MockMvc;
//import org.springframework.test.web.servlet.MvcResult;
//import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
//import org.springframework.test.web.servlet.setup.MockMvcBuilders;
//import org.springframework.web.context.WebApplicationContext;
//
//import com.albanero.authservice.AuthenticationServiceApplication;
//import com.albanero.authservice.common.dto.AuthRequest;
//import com.albanero.authservice.common.dto.response.AuthResponse;
//import com.albanero.authservice.common.dto.response.BaseResponse;
//import com.albanero.authservice.common.util.JwtUtil;
//import com.albanero.authservice.service.AuthService;
//
//@RunWith(SpringJUnit4ClassRunner.class)
////@PowerMockRunnerDelegate(SpringRunner.class)
//@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = AuthenticationServiceApplication.class)
//@AutoConfigureMockMvc
//@TestPropertySource(properties = { "secret.key= ENC(avm3+z3r04bDhwVM3el4Xc4k3dfuWSKs)",
//"encrypt.key=ENC(3hclo5Ioh5XI5dIisXGMV7YJd1glZzVo)", "jasypt.encryptor.password=alroKey@1234", "spring.data.mongodb.host=localhost",
//"spring.data.mongodb.port=27017",
//"spring.data.mongodb.database=users"})
//@PrepareForTest({ JwtUtil.class })
//public class AuthControllerIntegrationTest {
//	private static final Logger LOGGER = LoggerFactory.getLogger(AuthControllerTest.class);
//	private static final String ACCESS_TOKEN = "token.token.token";
//	private static final String REFRESH_JWT = "refresh.refresh.refresh";
//	private static final String REFRESH_TOKEN = "refreshtoken";
//	private static final String REFRESH_TOKEN_ENC = "refreshtoken";
//	private static final String USERNAME = "test_username";
//	private static final String PASSWORD = "test_password";
//
//	@Autowired
//	private WebApplicationContext wac;
//
//	@Autowired
//	private MockMvc mockMvc;
//	
//	@Autowired
//	private AuthService authService;
//	
//	@Autowired
//	private JwtUtil jwtUtil;
//	
//	@Before
//	public void setUp() throws Exception {
//		this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
//	}
//	
//	private UserDetails getUserDetails() {
//		AuthRequest user = new AuthRequest();
//		user.setPassword(PASSWORD);
//		user.setUsername(USERNAME);
//		return new User(user.getUsername(), user.getPassword(), new ArrayList<>());
//	}
//
//	private AuthRequest getAuthRequest() {
//		AuthRequest authRequest = new AuthRequest();
//		authRequest.setUsername("");
//		authRequest.setPassword("");
//		return authRequest;
//	}
//	
////	@Test
////	public void givenWac_whenServletContext_thenItProvidesGreetController() {
////	    ServletContext servletContext = wac.getServletContext();
////	    
////	    Assert.assertNotNull(servletContext);
////	    Assert.assertTrue(servletContext instanceof MockServletContext);
////	    Assert.assertNotNull(wac.getBean("authController"));
////	}
//	
//	@Test
//	public void createAuthenticationTokenTest_Success1() {
//		try {
//			when(authService.extractJwtFromRequest(Mockito.<HttpServletRequest>any())).thenReturn(REFRESH_TOKEN_ENC);
//			when(authService.isRTPresent(Mockito.<String>any())).thenReturn(true);
//			when(authService.validateRefreshToken(Mockito.<String>any())).thenReturn(true);
//			when(authService.getDecodedRefreshToken(Mockito.<String>any())).thenReturn(REFRESH_TOKEN);
//			when(jwtUtil.getUsernameFromToken(Mockito.<String>any())).thenReturn(USERNAME);
//			when(authService.loadUserByUsername(Mockito.<String>any())).thenReturn(getUserDetails());
//			when(jwtUtil.generateToken(Mockito.<UserDetails>any(), "access")).thenReturn(ACCESS_TOKEN);
//			MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.post("/authenticate")
//					.param("username", "").param("password", "")).andExpect(status().isOk()).andReturn();	
//
//		} catch (Exception e) {
//			LOGGER.error(
//					"Inside LoginControllerTest::createAuthenticationTokenTest_Success1 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//	
//	@Test
//	public void createAuthenticationTokenTest_Success2() {
//		try {
//			PowerMockito.mockStatic(JwtUtil.class);
//			LOGGER.debug("Inside LoginControllerTest::createAuthenticationTokenTest_Success2 Method");
//			when(authService.loadUserByUsername(Mockito.<String>any())).thenReturn(getUserDetails());
//			when(jwtUtil.generateToken(Mockito.<UserDetails>any(), "access")).thenReturn(ACCESS_TOKEN);
//			when(jwtUtil.generateToken(Mockito.<UserDetails>any(), "refresh")).thenReturn(REFRESH_JWT);
//			when(authService.saveRefreshToken(Mockito.<String>any(), Mockito.<String>any())).thenReturn(REFRESH_TOKEN_ENC);
//			MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.post("/authenticate")
//					.param("username", USERNAME).param("password", PASSWORD)).andExpect(status().isOk()).andReturn();
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::createAuthenticationTokenTest_Success2 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//	
//	@Test
//	public void createAuthenticationTokenTest_Failure1() {
//		try {
//			PowerMockito.mockStatic(JwtUtil.class);
//			LOGGER.debug("Inside LoginControllerTest::createAuthenticationTokenTest_Failure1 Method");
////			when(authService.extractJwtFromRequest(Mockito.<HttpServletRequest>any())).thenReturn(REFRESH_JWT);
//			MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.post("/authenticate")
//					.param("username", USERNAME).param("password", PASSWORD)).andExpect(status().isOk()).andReturn();
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::createAuthenticationTokenTest_Failure1 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//	
//	@Test
//	public void createAuthenticationTokenTest_Failure2() {
//		try {
//			PowerMockito.mockStatic(JwtUtil.class);
//			LOGGER.debug("Inside LoginControllerTest::createAuthenticationTokenTest_Success2 Method");
//			when(authService.extractJwtFromRequest(Mockito.<HttpServletRequest>any())).thenReturn(REFRESH_TOKEN_ENC);
//			when(authService.isRTPresent(Mockito.<String>any())).thenReturn(false);
//			MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.post("/authenticate")
//					.param("username", USERNAME).param("password", PASSWORD)).andExpect(status().isOk()).andReturn();
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::createAuthenticationTokenTest_Success2 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//	
//	@Test
//	public void createAuthenticationTokenTest_Failure3() {
//		try {
//			PowerMockito.mockStatic(JwtUtil.class);
//			LOGGER.debug("Inside LoginControllerTest::createAuthenticationTokenTest_Success2 Method");
//			when(authService.extractJwtFromRequest(Mockito.<HttpServletRequest>any())).thenReturn(REFRESH_TOKEN_ENC);
//			when(authService.isRTPresent(Mockito.<String>any())).thenReturn(true);
//			when(authService.validateRefreshToken(Mockito.<String>any())).thenReturn(false);
//			MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/authenticate")
//					.param("username", USERNAME).param("password", PASSWORD)).andExpect(status().isOk()).andReturn();
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::createAuthenticationTokenTest_Success2 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//	
//	@Test
//	public void isRefreshTokenValidTest_Success1() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::isRefreshTokenValidTest_Success1 Method");
//			when(authService.isRTPresent(Mockito.<String>any())).thenReturn(true);
//			when(authService.validateRefreshToken(Mockito.<String>any())).thenReturn(true);
//			MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/refresh-token/validate/{refreshToken}",REFRESH_TOKEN_ENC))
//					.andDo(print()).andExpect(status().isOk()).andReturn();
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::isRefreshTokenValidTest_Success1 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//	
//	@Test
//	public void isRefreshTokenValidTest_Success2() {
//		try {
//			LOGGER.debug("Inside LoginControllerTest::isRefreshTokenValidTest_Success2 Method");
//			when(authService.isRTPresent(Mockito.<String>any())).thenReturn(true);
//			when(authService.validateRefreshToken(Mockito.<String>any())).thenReturn(false);
//			MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/refresh-token/validate/{refreshToken}",REFRESH_TOKEN_ENC))
//					.andDo(print()).andExpect(status().isOk()).andReturn();
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::isRefreshTokenValidTest_Success2 method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//	
//	@Test
//	public void isRefreshTokenValidTest_Failure() {
//		try {
//			PowerMockito.mockStatic(JwtUtil.class);
//			LOGGER.debug("Inside LoginControllerTest::isRefreshTokenValidTest_Failure Method");
//			when(authService.isRTPresent(Mockito.<String>any())).thenReturn(false);
//
//			MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/refresh-token/validate/{refreshToken}",REFRESH_TOKEN_ENC))
//					.andDo(print()).andExpect(status().isOk()).andReturn();
//		} catch (Exception e) {
//			LOGGER.error("Inside LoginControllerTest::isRefreshTokenValidTest_Failure method : Unknown error {} ",
//					e.getMessage(), e);
//		}
//	}
//}
