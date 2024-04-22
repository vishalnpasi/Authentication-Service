package com.albanero.authservice.service;

import com.albanero.authservice.common.dto.request.UserIdDetails;
import com.albanero.authservice.common.dto.response.FetchResponse;
import org.springframework.http.ResponseEntity;

public interface TokenService {

    ResponseEntity<String> generateAccessToken(UserIdDetails userIdDetails);

    ResponseEntity<String> generateRefreshToken(UserIdDetails userIdDetails);

    ResponseEntity<String> getHashedRefreshToken(String refreshToken);

    ResponseEntity<String> getUsernameFromToken(String verificationCode);

    ResponseEntity<Boolean> validateToken(String token);

    Boolean validateTokenFromTokenService(String verificationCode);

    ResponseEntity<FetchResponse> getFetchResponseFromToken(String fetchResponseToken);

    Boolean validateTokenRestTemplate(String token);
}
