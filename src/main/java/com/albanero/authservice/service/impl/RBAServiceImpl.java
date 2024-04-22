package com.albanero.authservice.service.impl;

import com.albanero.authservice.common.constants.AuthConstants;
import com.albanero.authservice.common.constants.RBAConstants;
import com.albanero.authservice.common.dto.response.BaseResponse;
import com.albanero.authservice.common.dto.response.FetchResponse;
import com.albanero.authservice.common.util.WebClientUtil;
import com.albanero.authservice.exception.RBAServiceException;
import com.albanero.authservice.exception.TokenServiceException;
import com.albanero.authservice.service.RBAService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Optional;

import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.RBA_SERVICE_EXCEPTION;
import static com.albanero.authservice.common.constants.LoggerConstants.*;

@Service
public class RBAServiceImpl implements RBAService {

    private static final Logger LOGGER = LoggerFactory.getLogger(RBAServiceImpl.class);

    private static final String RBA_SERVICE = "rba-service";

    private static final String RBA_SERVICE_IMPL_CLASS = "RBAServiceImpl";

    private final DiscoveryClient discoveryClient;

    private final WebClientUtil webClientUtil;

    @Autowired
    public RBAServiceImpl(DiscoveryClient discoveryClient, WebClientUtil webClientUtil) {
        this.discoveryClient = discoveryClient;
        this.webClientUtil = webClientUtil;
    }

    @Override
    public FetchResponse fetchRequestDetails(HttpServletRequest request) {
        final String method = "fetchRequestDetails";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, RBA_SERVICE_IMPL_CLASS, method);
        long startTime = System.currentTimeMillis();
        try {
            Optional<URI> optUri = discoveryClient.getInstances(RBA_SERVICE).stream().map(ServiceInstance::getUri).findFirst()
                    .map(s -> s.resolve(RBAConstants.REQUEST_DETAILS));
            if (optUri.isPresent()) {
                ResponseEntity<FetchResponse> requestDetailsResponse = webClientUtil.get(String.valueOf(optUri.get()), null,
                        FetchResponse.class);
                LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, RBA_SERVICE_IMPL_CLASS, method, (System.currentTimeMillis() - startTime));
                return requestDetailsResponse.getBody();
            }
            throw new RBAServiceException(RBA_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception ex) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, RBA_SERVICE_IMPL_CLASS, method, ex.getMessage(), "", ex);
            throw new RBAServiceException(RBA_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @SneakyThrows(JsonProcessingException.class)
    @Override
    public ResponseEntity<BaseResponse> updateAuthService(String userId, FetchResponse fetchResponse) {
        final String method = "updateAuthService";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, RBA_SERVICE_IMPL_CLASS, method);
        long startTime = System.currentTimeMillis();
        try {
            Optional<URI> optUri = discoveryClient.getInstances(RBA_SERVICE).stream().map(ServiceInstance::getUri).findFirst()
                    .map(s -> s.resolve(RBAConstants.UPDATE_AUTH_HISTORY));
            if (optUri.isPresent()) {
                ResponseEntity<BaseResponse> baseResponse = webClientUtil.post(optUri.get() + userId, null, fetchResponse, BaseResponse.class);
                LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, RBA_SERVICE_IMPL_CLASS, method, (System.currentTimeMillis() - startTime));
                return baseResponse;
            }
            throw new RBAServiceException(RBA_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (WebClientResponseException resException) {
            BaseResponse baseResponse = new ObjectMapper().readValue(resException.getResponseBodyAsString(), BaseResponse.class);
            throw new TokenServiceException(baseResponse.getMessage(), resException.getStatusCode());
        } catch (Exception ex) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, RBA_SERVICE_IMPL_CLASS, method, ex.getMessage(), ex.getStackTrace());
            throw new RBAServiceException(RBA_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public ResponseEntity<FetchResponse> getFetchResFromToken(String token) {
        final String method = "getFetchResFromToken";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, RBA_SERVICE_IMPL_CLASS, method);
        long startTime = System.currentTimeMillis();
        try {
            Optional<URI> optUri = discoveryClient.getInstances("token-service").stream().map(ServiceInstance::getUri).findFirst()
                    .map(s -> s.resolve(AuthConstants.GET_FETCH_RESPONSE_FROM_TOKEN));
            if (optUri.isPresent()) {
                ResponseEntity<FetchResponse> baseResponse = webClientUtil.get(optUri.get() + token, null, FetchResponse.class);
                LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, RBA_SERVICE_IMPL_CLASS, method, (System.currentTimeMillis() - startTime));
                return baseResponse;
            }
            throw new RBAServiceException(RBA_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception ex) {
            LOGGER.error(AUTHENTICATION_SERVICE_STACK_TRACE_ERROR_LOG_TAG, RBA_SERVICE_IMPL_CLASS, method, ex.getMessage(), ex.getStackTrace());
            throw new RBAServiceException(RBA_SERVICE_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
