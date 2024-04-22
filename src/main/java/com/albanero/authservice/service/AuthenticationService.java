package com.albanero.authservice.service;

import com.albanero.authservice.common.dto.request.AuthRequest;
import com.albanero.authservice.common.dto.request.SecurityQuesRequest;
import com.albanero.authservice.common.dto.response.AuthResponse;
import com.albanero.authservice.common.dto.response.BaseResponse;
import com.albanero.authservice.common.dto.response.FetchResponse;
import com.albanero.authservice.common.dto.response.ProductRoles;
import com.albanero.authservice.model.ProductRoleDetails;
import com.albanero.authservice.model.UserProfile;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

@Service
@RefreshScope
public interface AuthenticationService {

    BaseResponse authenticate(HttpServletRequest request, AuthRequest authenticationRequest);

    BaseResponse authenticateMFA(HttpServletRequest request, AuthRequest authenticationRequest);

    UserDetails loadUserByUserProfile(UserProfile userProfile);

    public UserProfile loadUserProfileByMailId(String mail) throws UsernameNotFoundException;
    public UserProfile loadUserProfileByUsernameOrEmail(String identifier);

    public UserProfile loadUserProfileByUsername(String mail) throws UsernameNotFoundException;

    String saveRefreshTokenAfterGLogin(String refreshToken, String username);

    AuthResponse generateToken(String username);

    BaseResponse verify(AuthRequest verifyCodeRequest);

    Boolean checkForMfa(String usermail);

    Boolean checkMfa(HttpServletRequest request);

    List<ProductRoles> checkForProductLevelDetails(List<ProductRoleDetails> productDetails);

    String generateSecretKey();

    BaseResponse validateAccessToken(HttpServletRequest request);

    String validateInternalAuthToken(String token);

    BaseResponse generateInternalToken(String userId, String secretToken);

    BaseResponse saveSecurityQuestion(HttpServletRequest request, SecurityQuesRequest securityQuesRequest);

    BaseResponse getSecurityQuestion(String username);

    BaseResponse getSecurityQuestions();

    BaseResponse checkForSQ(String username);

    BaseResponse checkSecurityQuestion(String username, SecurityQuesRequest securityQuesRequest);

    BaseResponse riskLevelCheck(UserProfile userProfile, FetchResponse fetchResponse);

    Boolean saveAuthHistory(String userId, FetchResponse fetchResponse);

    BaseResponse securityChecks(String username, FetchResponse fetchResponse);

    void blockDevice(String userId, FetchResponse fetchResponse);

    BaseResponse incrementFailedAttempts(String userId, FetchResponse fetchResponse);

    BaseResponse resetFailedAttempts(String userId);

    BaseResponse authenticateOtpPasscode(HttpServletRequest httpServletRequest, String usermail, String passcode);

    BaseResponse checkForPassword(HttpServletRequest httpServletRequest, String password);

    BaseResponse validateRefreshToken (String refreshToken);

    BaseResponse generateNewAccessToken(HttpServletRequest httpServletRequest, String refreshToken, AuthRequest authRequest);
}
