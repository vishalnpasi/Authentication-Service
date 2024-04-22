package com.albanero.authservice.service;

import com.albanero.authservice.common.dto.request.*;
import com.albanero.authservice.common.dto.response.BaseResponse;
import com.albanero.authservice.model.UserSession;
import org.springframework.web.multipart.MultipartFile;


import jakarta.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.util.List;

public interface UserService {
    BaseResponse save(RegistrationUser user, HttpServletRequest request);

    BaseResponse generateMfaQrAndSecret(HttpServletRequest request , RegistrationUser user);

    boolean verify(String verificationCode);

    BaseResponse resendVerificationLink(HttpServletRequest request, String email);

    BaseResponse requestForAccountApproval(HttpServletRequest request, String code);

    BaseResponse approve(String email, Boolean isAccountApproved, RegistrationUser registrationUser);

    BaseResponse registerForGoogleLogin(RegistrationUser user);

    BaseResponse checkPasscode(String mailId, String passcode);

    BaseResponse savePassword(ChangePasswordRequest changePasswordRequest);

    BaseResponse addPasscode(String mailId, String passcode);

    BaseResponse validateUserForGLogin(String username);

    BaseResponse updateUser(HttpServletRequest request, RegistrationUser updatedUser);

    BaseResponse updateUser2FA(HttpServletRequest request) throws UnsupportedEncodingException;

    BaseResponse getUser(HttpServletRequest request, AuthRequest authRequest);

    BaseResponse deleteUser(String id);

    BaseResponse updateAndSaveUser2FA(Boolean use2FA, String secret, HttpServletRequest request);

    UserSession saveRToken(UserSessionRequestDto userSession);

    BaseResponse changePassword(String token, String oldPassword, String newPassword, String confirmedPassword);

    Boolean verifyUserAccess(HttpServletRequest request, String productId);

    BaseResponse fetchUsername(HttpServletRequest request, String id);

    BaseResponse getProductDetails(HttpServletRequest request);

    String fetchEmail(HttpServletRequest request);

    BaseResponse uploadProfilePicture(HttpServletRequest request, MultipartFile file);

    BaseResponse saveSQ(ChangeSQRequest changeSQRequest);

    BaseResponse checkPassword(HttpServletRequest request, String password);

    BaseResponse deleteChangeSecuritySettings(String id);

    BaseResponse fetchUserDetailsFromUserId(String userId,HttpServletRequest httpServletRequest);

    BaseResponse fetchUserDetailsList(List<String> userIds);

    BaseResponse changeUserAccountStatus(UserAccountStatus userAccountStatus, HttpServletRequest httpServletRequest);

    BaseResponse unblockUserRequest(HttpServletRequest request, RegistrationUser registrationUser);

    BaseResponse unblockUser(RegistrationUser registrationUser) throws UnsupportedEncodingException;

    BaseResponse fetchUserNameFromToken(HttpServletRequest httpServletRequest);

    String saveRefreshToken(String refreshToken, String username);

    BaseResponse fetchUserDetailsByUserIdAndProjectId(String projectId, String userId);

    BaseResponse setDefaultProjectOrgRole(String defaultProjectOrgRoleId);

}
