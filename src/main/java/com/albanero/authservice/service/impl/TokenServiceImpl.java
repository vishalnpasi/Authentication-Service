package com.albanero.authservice.service.impl;

import com.albanero.authservice.common.constants.AuthConstants;
import com.albanero.authservice.common.constants.TokenConstants;
import com.albanero.authservice.common.dto.request.UserIdDetails;
import com.albanero.authservice.common.dto.response.FetchResponse;
import com.albanero.authservice.common.util.RestUtil;
import com.albanero.authservice.common.util.WebClientUtil;
import com.albanero.authservice.exception.TokenServiceException;
import com.albanero.authservice.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Optional;

import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.TOKEN_SERVICE_EXCEPTION;
import static com.albanero.authservice.common.constants.LoggerConstants.*;

@Service
public class TokenServiceImpl implements TokenService {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenServiceImpl.class);

    private static final String TOKEN_SERVICE = "token-service";
    private static final String TOKEN_SERVICE_IMPL_CLASS = "TokenServiceImpl";

    private final DiscoveryClient discoveryClient;

    private final WebClientUtil webClientUtil;

    @Autowired
    public TokenServiceImpl(DiscoveryClient discoveryClient, WebClientUtil webClientUtil) {
        this.discoveryClient = discoveryClient;
        this.webClientUtil = webClientUtil;
    }

    @Override
    public ResponseEntity<String> generateAccessToken(UserIdDetails userIdDetails) {
        final String method = "generateAccessToken";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method);
        long startTime = System.currentTimeMillis();
        try {
            Optional<URI> optUri = discoveryClient.getInstances(TOKEN_SERVICE).stream().map(ServiceInstance::getUri).findFirst()
                    .map(s -> s.resolve(AuthConstants.GENERATE_TOKEN));
            if (optUri.isPresent()) {
                ResponseEntity<String> accessToken = webClientUtil.post(optUri.get() + TokenConstants.ACCESS, null, userIdDetails, String.class);
                LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method, (System.currentTimeMillis() - startTime));
                return accessToken;
            }
            throw new TokenServiceException(TOKEN_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception ex) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method, ex.getMessage(), ex.getStackTrace());
            throw new TokenServiceException(TOKEN_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public ResponseEntity<String> generateRefreshToken(UserIdDetails userIdDetails) {
        final String method = "generateRefreshToken";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method);
        long startTime = System.currentTimeMillis();
        try {
            Optional<URI> optUri = discoveryClient.getInstances(TOKEN_SERVICE).stream().map(ServiceInstance::getUri).findFirst()
                    .map(s -> s.resolve(AuthConstants.GENERATE_TOKEN));
            if (optUri.isPresent()) {
                ResponseEntity<String> refreshToken = webClientUtil.post(optUri.get() + TokenConstants.REFRESH, null, userIdDetails, String.class);
                LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method, (System.currentTimeMillis() - startTime));
                return refreshToken;
            }
            throw new TokenServiceException(TOKEN_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception ex) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method, ex.getMessage(), ex.getStackTrace());
            throw new TokenServiceException(TOKEN_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public ResponseEntity<String> getHashedRefreshToken(String refreshToken) {
        final String method = "getHashedRefreshToken";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method);
        long startTime = System.currentTimeMillis();
        try {
            Optional<URI> optUri = discoveryClient.getInstances(TOKEN_SERVICE).stream().map(ServiceInstance::getUri).findFirst()
                    .map(s -> s.resolve(AuthConstants.GET_ENCODED_TOKEN));
            if (optUri.isPresent()) {
                ResponseEntity<String> hashedRefreshToken = RestUtil.get(optUri.get() + refreshToken, null, String.class);
                LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method, (System.currentTimeMillis() - startTime));
                return hashedRefreshToken;
            }
            throw new TokenServiceException(TOKEN_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception ex) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method, ex.getMessage(), ex.getStackTrace());
            throw new TokenServiceException(TOKEN_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public ResponseEntity<String> getUsernameFromToken(String verificationCode) {
        final String method = "getUsernameFromToken";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method);
        long startTime = System.currentTimeMillis();
        try {
            Optional<URI> optUri = discoveryClient.getInstances(TOKEN_SERVICE).stream().map(ServiceInstance::getUri).findFirst()
                    .map(s -> s.resolve(AuthConstants.USERNAME));
            if (optUri.isPresent()) {
                ResponseEntity<String> usernameFromToken = RestUtil.get(optUri.get() + verificationCode, null, String.class);
                LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method, (System.currentTimeMillis() - startTime));
                return usernameFromToken;
            }
            throw new TokenServiceException(TOKEN_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception ex) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method, ex.getMessage(), ex.getStackTrace());
            throw new TokenServiceException(TOKEN_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public ResponseEntity<Boolean> validateToken(String token) {
        final String method = "validateToken";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method);
        long startTime = System.currentTimeMillis();
        try {
            Optional<URI> optUri = discoveryClient.getInstances(TOKEN_SERVICE).stream().map(si -> si.getUri()).findFirst()
                    .map(s -> s.resolve(AuthConstants.VALIDATE_TOKEN_FROM_TOKEN_SERVICE));
            if (optUri.isPresent()) {
                ResponseEntity<Boolean> isValidToken = RestUtil.get(optUri.get() + token, null, Boolean.class);
                LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method, (System.currentTimeMillis() - startTime));
                return isValidToken;
            }
            throw new TokenServiceException(TOKEN_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception ex) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method, ex.getMessage(), ex.getStackTrace());
            throw new TokenServiceException(TOKEN_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public Boolean validateTokenFromTokenService(String verificationCode) {
        final String method = "validateTokenFromTokenService";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method);
        long startTime = System.currentTimeMillis();
        try {
            Optional<URI> optUri = discoveryClient.getInstances(TOKEN_SERVICE).stream().map(si -> si.getUri()).findFirst()
                    .map(s -> s.resolve(AuthConstants.VALIDATE_TOKEN_FROM_TOKEN_SERVICE));
            if (optUri.isPresent()) {
                ResponseEntity<Boolean> responseEntity = RestUtil.get(optUri.get() + verificationCode, null, Boolean.class);
                if (responseEntity != null) {
                    LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method, (System.currentTimeMillis() - startTime));
                    return responseEntity.getBody();
                }
            }
            throw new TokenServiceException(TOKEN_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception ex) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method, ex.getMessage(), ex.getStackTrace());
            throw new TokenServiceException(TOKEN_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        }


    }

    @Override
    public ResponseEntity<FetchResponse> getFetchResponseFromToken(String token) {
        final String method = "getFetchResponseFromToken";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method);
        long startTime = System.currentTimeMillis();
        try {
            Optional<URI> optUri = discoveryClient.getInstances(TOKEN_SERVICE).stream().map(si -> si.getUri()).findFirst()
                    .map(s -> s.resolve(AuthConstants.GET_FETCH_RESPONSE_FROM_TOKEN));
            if (optUri.isPresent()) {
                ResponseEntity<FetchResponse> responseEntity = webClientUtil.get(optUri.get() + token, null, FetchResponse.class);
                if (responseEntity != null) {
                    LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method, (System.currentTimeMillis() - startTime));
                    return responseEntity;
                }
            }
            throw new TokenServiceException(TOKEN_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception ex) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, method, ex.getMessage(), ex.getStackTrace());
            throw new TokenServiceException(TOKEN_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }


    public Boolean validateTokenRestTemplate(String token) {
        String methodName = "validateTokenRestTemplate";
        try {
            LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, methodName);
            long startTime = System.currentTimeMillis();
			Optional<URI> optUri = discoveryClient.getInstances(TOKEN_SERVICE).stream().map(ServiceInstance::getUri).findFirst()
					.map(s -> s.resolve(AuthConstants.VALIDATE_TOKEN_FROM_TOKEN_SERVICE));
            if (optUri.isPresent()) {
                String uri = optUri.get() + "token";
                HttpHeaders headers = new HttpHeaders();
                headers.add(HttpHeaders.AUTHORIZATION, token);
                HttpEntity<Object> httpEntity = new HttpEntity<>(null, headers);
                RestTemplate restTemplate = new RestTemplate();
                ResponseEntity<Boolean> isTokenValidResponse = restTemplate.exchange(uri,
                        HttpMethod.GET, httpEntity, Boolean.class);
                LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, methodName,(System.currentTimeMillis() - startTime));
                return isTokenValidResponse.getBody();
            }
            LOGGER.info(AUTHENTICATION_SERVICE_ERROR_LOG_TAG, TOKEN_SERVICE_IMPL_CLASS, methodName,"OptUri is Empty.");
            return false;
        } catch (Exception ex) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG,TOKEN_SERVICE_IMPL_CLASS,methodName,ex.getMessage(),ex.getStackTrace());
            return false;
        }
    }
}
