package com.albanero.authservice.service;

import com.albanero.authservice.common.dto.response.BaseResponse;
import com.albanero.authservice.common.dto.response.FetchResponse;
import org.springframework.http.ResponseEntity;

import jakarta.servlet.http.HttpServletRequest;

public interface RBAService {

    FetchResponse fetchRequestDetails(HttpServletRequest request);

    ResponseEntity<BaseResponse> updateAuthService(String userId, FetchResponse fetchResponse);

    ResponseEntity<FetchResponse> getFetchResFromToken(String token);
}
