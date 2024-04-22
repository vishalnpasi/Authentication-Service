package com.albanero.authservice.filter;

import com.albanero.authservice.common.constants.AllowedEndpoints;
import com.albanero.authservice.common.constants.AuthConstants;
import com.albanero.authservice.common.dto.request.UserIdDetails;
import com.albanero.authservice.common.dto.response.BaseResponse;
import com.albanero.authservice.common.util.HelperUtil;
import com.albanero.authservice.common.util.RequestUtil;
import com.albanero.authservice.common.util.RestUtil;
import com.albanero.authservice.config.CorsConfig;
import com.albanero.authservice.exception.AuthenticationFilterException;
import com.albanero.authservice.model.AccountStatus;
import com.albanero.authservice.model.UserProfile;
import com.albanero.authservice.model.UserSession;
import com.albanero.authservice.repository.AccStatusRepository;
import com.albanero.authservice.repository.UserSessionRepository;
import com.albanero.authservice.service.TokenService;
import com.albanero.authservice.service.UserRoleService;
import com.albanero.authservice.service.impl.AuthServiceImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;

import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.HTTP_REST_API_IS_UNAUTHORIZED;
import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.TOKEN_SERVICE_EXCEPTION;
import static com.albanero.authservice.common.constants.LoggerConstants.*;
import static com.albanero.authservice.common.constants.RequestParams.USER_ID;

/**
 * Request Filter for each HTTP REST API
 *
 * @author arunima.mishra
 */
@Component
public class AuthenticationFilter extends OncePerRequestFilter {

	private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationFilter.class);

	private static final String AUTHENTICATION_FILTER_CLASS = "AuthenticationFilter";

	private final AntPathMatcher antPathMatcher = new AntPathMatcher();

	private final AuthServiceImpl authService;

	private final DiscoveryClient discoveryClient;

	private final AccStatusRepository accStatusRepo;

	private final UserSessionRepository userSessionRepo;

	private final UserRoleService userRoleService;

	private final RequestUtil requestUtil;

	private final TokenService tokenService;

	private final CorsConfig corsConfig;

	@Autowired
	public AuthenticationFilter(AuthServiceImpl authService, DiscoveryClient discoveryClient, CorsConfig corsConfig,
								AccStatusRepository accStatusRepo, UserSessionRepository userSessionRepo,
								UserRoleService userRoleService, RequestUtil requestUtil, TokenService tokenService) {
		this.authService = authService;
		this.discoveryClient = discoveryClient;
		this.accStatusRepo = accStatusRepo;
		this.userSessionRepo = userSessionRepo;
		this.userRoleService = userRoleService;
		this.requestUtil = requestUtil;
		this.tokenService = tokenService;
		this.corsConfig = corsConfig;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String method = "doFilterInternal";
		ObjectMapper mapper = new ObjectMapper();

		String path = request.getServletPath();

		try {
			setResponseHeaders(request, response);

			if(HttpMethod.OPTIONS.name().equalsIgnoreCase(request.getMethod())) {
				LOGGER.info("Options call");
				response.setContentType("application/json");
				response.setStatus(HttpServletResponse.SC_OK);
				response.getWriter().write(new char[]{});
				return;
			}

			String jwtToken = requestUtil.extractJwtFromRequest(request);

			String username;
				if (shouldAuthenticate(path) && StringUtils.hasText(jwtToken) && Boolean.TRUE.equals(tokenService.validateTokenRestTemplate(jwtToken))) {
				URI uri = discoveryClient.getInstances("token-service").stream().map(ServiceInstance::getUri).findFirst()
						.map(s -> s.resolve(AuthConstants.USER_MAPPINGS))
						.orElseThrow(() -> new AuthenticationFilterException(TOKEN_SERVICE_EXCEPTION.label));
				BaseResponse userIdDetailsResponse = Objects.requireNonNull(RestUtil.get(uri + jwtToken, null, BaseResponse.class)).getBody();
				UserIdDetails userIdDetails;
				if (userIdDetailsResponse != null) {
					userIdDetails = mapper.convertValue(userIdDetailsResponse.getPayload(), UserIdDetails.class);
				} else {
					userIdDetails = mapper.convertValue("{}", UserIdDetails.class);
				}

				if (userIdDetails != null && userIdDetails.getUserProfileDetails() != null
							&& userIdDetails.getUserProfileDetails().getUsername() != null
						&& SecurityContextHolder.getContext().getAuthentication() == null) {
					username = userIdDetails.getUserProfileDetails().getUsername();
					UserProfile userProfile = authService.loadUserProfileByUsername(username);
					AccountStatus accStatus = accStatusRepo.findByUserId(userProfile.getId());
					String getUserAccountStatus = HelperUtil.getUserAccountStatus(accStatus);
					validateIfUserAcctIsActive(getUserAccountStatus, userProfile, response);
					String userId = userProfile.getId();
					UserSession dbUser = userSessionRepo.findByUserId(userId);

					failedAttempts(dbUser, request, response, userProfile, request);
				}
			} else {
				filterChain.doFilter(request, response);
				return;
			}
		} catch (BadCredentialsException ex) {
			LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, AUTHENTICATION_FILTER_CLASS, method, ex.getMessage(), ex.getStackTrace());
			request.setAttribute("exception", ex);
		} catch (Exception ex) {
			LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, AUTHENTICATION_FILTER_CLASS, method, ex.getMessage(), ex.getStackTrace());
		}
		filterChain.doFilter(request, response);
	}

	private static void validateIfUserAcctIsActive(String getUserAccountStatus,UserProfile userProfile, HttpServletResponse httpResponse) throws IOException {
		if (!Objects.equals(getUserAccountStatus, AuthConstants.ACCOUNT_ACTIVE)) {
			LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG,AUTHENTICATION_FILTER_CLASS, "validateIfUserAcctIsActive", "Account is not active.",USER_ID, userProfile.getId());
			httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, getUserAccountStatus);
		}
	}

	private void failedAttempts(UserSession dbUser, HttpServletRequest httpRequest, HttpServletResponse httpResponse, UserProfile userProfile, HttpServletRequest request) throws IOException, URISyntaxException {
		String method = "failedAttempts";
		if (dbUser.getFailedAttempts() < 3) {
			if (dbUser.getHashedRT().length() == 16 && dbUser.getEncryptedRT().length() == 16) {
				LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG,AUTHENTICATION_FILTER_CLASS,method, "HTTP REST API is Unauthorized ",USER_ID,userProfile.getId());
				httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, HTTP_REST_API_IS_UNAUTHORIZED.toString());
				return;
			}

			setAuthentication(httpRequest,httpResponse, userProfile);

			Boolean authorizeIamRoute = userRoleService.authorizeIamRoutes(request, userProfile);
			if(Boolean.FALSE.equals(authorizeIamRoute)) {
				LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG,AUTHENTICATION_FILTER_CLASS,method, "AuthorizeIamRoute Failed",USER_ID,userProfile.getId());
				httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
				httpResponse.setContentType("application/json");
				httpResponse.getWriter().write("{\"message\": \"Unauthorized Access\"}");
			}
		} else {
			LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG,AUTHENTICATION_FILTER_CLASS,method, "HTTP REST API is Unauthorized",USER_ID,userProfile.getId());
			httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, HTTP_REST_API_IS_UNAUTHORIZED.toString());
		}
	}

	private void setResponseHeaders(HttpServletRequest request, HttpServletResponse response) {
		String origin = request.getHeader("origin");
		LOGGER.info("request origin  : {}", origin);
		if (corsConfig.isOriginAllowed(origin)) {
			response.setHeader("Access-Control-Allow-Origin", origin);
		}
		response.setHeader("Access-Control-Allow-Credentials", "true");
		response.setHeader("Access-Control-Allow-Methods", "POST, PUT, GET, PATCH, OPTIONS, DELETE");
		response.setHeader("Access-Control-Max-Age", "3600");
		response.setHeader("Access-Control-Allow-Headers",
				"Content-Type, Accept, X-Requested-With, remember-me, Authorization, Accept-Encoding, X-Project-Id, X-Org-Id, X-Org-Level"
		);
	}

	private void setAuthentication(HttpServletRequest httpRequest, HttpServletResponse httpResponse, UserProfile userProfile) {
		String method = "setAuthentication";
		LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,AUTHENTICATION_FILTER_CLASS,method);
		long startTime = System.currentTimeMillis();
		UserDetails userDetails = this.authService.loadUserByUserProfile(userProfile);
		if (userDetails != null) {
			LOGGER.info(AUTHENTICATION_SERVICE_LOG_TAG_WITH_MESSAGE,AUTHENTICATION_FILTER_CLASS,method,"setting UsernamePasswordAuthenticationToken");
			UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
					userDetails, null, userDetails.getAuthorities());
			usernamePasswordAuthenticationToken
					.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpRequest));
			SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, AUTHENTICATION_FILTER_CLASS, method, (System.currentTimeMillis() - startTime));
		} else {
			try {
				LOGGER.error(AUTHENTICATION_SERVICE_LOG_TAG_WITH_MESSAGE, AUTHENTICATION_FILTER_CLASS,method,"UserId details are null");
				httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "HTTP REST API is Unauthorized");
			} catch (IOException ex) {
				throw new AuthenticationFilterException(ex.getMessage());
			}
		}
	}

	private boolean shouldAuthenticate(String path) {
		LOGGER.debug("Incoming path: {}", path);
		for(String uri: AllowedEndpoints.getAllowedEndPoints()) {
			LOGGER.debug("Matching with {}, result is: {}", uri, antPathMatcher.match(uri, path));
			if(antPathMatcher.match(uri, path)) {
				return false;
			}
		}
		return true;
	}

}