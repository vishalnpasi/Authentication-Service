package com.albanero.authservice.common.util;

import com.albanero.authservice.common.constants.AuthConstants;
import com.albanero.authservice.common.constants.RBAConstants;
import com.albanero.authservice.common.dto.request.AddRemoveMemberRequest;
import com.albanero.authservice.common.dto.request.UserIdDetails;
import com.albanero.authservice.common.dto.response.BaseResponse;
import com.albanero.authservice.common.dto.response.FetchResponse;
import com.albanero.authservice.common.dto.response.RiskResponse;
import com.albanero.authservice.exception.RequestUtilException;
import com.albanero.authservice.model.UserProfile;
import com.albanero.authservice.model.UserSession;
import com.albanero.authservice.repository.UserSessionRepository;
import org.jasypt.util.text.BasicTextEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.ACTION_FAILED;
import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.INVALID_RT_TOKEN_EXCEPTION;
import static com.albanero.authservice.common.constants.LoggerConstants.*;
import static com.albanero.authservice.common.constants.RequestUtilConstants.*;

@Service
public class RequestUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(RequestUtil.class);
    private static final String REQUEST_UTIL = "RequestUtil";

    private URI uri;

    @Value("${jasyptSecret}")
    private String encryptorPassword;

    private final DiscoveryClient discoveryClient;

    private final WebClientUtil webClientUtil;

    private final UserSessionRepository userSessionRepo;

    @Autowired
    public RequestUtil(  WebClientUtil webClientUtil, UserSessionRepository userSessionRepo, DiscoveryClient discoveryClient) {
        this.webClientUtil = webClientUtil;
        this.userSessionRepo = userSessionRepo;
        this.discoveryClient = discoveryClient;
    }

    /**
     * Method to extract JWT from request
     *
     * @param request  {@link String}
     * @return String
     */
    public String extractJwtFromRequest(HttpServletRequest request) {
        try {
            String bearerToken = request.getHeader("Authorization");
            if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
                BasicTextEncryptor encryptor = new BasicTextEncryptor();
                encryptor.setPassword(encryptorPassword);
                bearerToken = bearerToken.substring(7);

                bearerToken = encryptor.decrypt(bearerToken);
                return bearerToken;
            }
            return null;
        } catch (Exception e) {
            LOGGER.warn(AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG, REQUEST_UTIL, "extractJwtFromRequest", e.getMessage(), e.getStackTrace());
            return e.getMessage();
        }
    }

    /**
     * Method to extract JWT from request
     *
     * @return String
     */
    public static String extractRtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,INVALID_RT_TOKEN_EXCEPTION, REQUEST_UTIL,"extractRtFromRequest");
        throw new RequestUtilException(INVALID_RT_TOKEN_EXCEPTION, HttpStatus.BAD_REQUEST);
    }

    /**
     * Method to get decoded refresh token
     *
     * @param hashedToken  {@link String}
     * @return String
     */
    public String getDecodedRefreshToken(String hashedToken) {
        try {
            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            encryptor.setPassword(encryptorPassword);

            UserSession userTokenDetails = userSessionRepo.findByHashedRT(hashedToken);
            String encryptedRT = userTokenDetails.getEncryptedRT();

            String refreshToken1 = encryptor.decrypt(encryptedRT);
            return encryptor.decrypt(refreshToken1);
        } catch (Exception e) {
            LOGGER.warn(AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG, REQUEST_UTIL, "getDecodedRefreshToken", e.getMessage(), e.getStackTrace());
            return e.getMessage();
        }
    }

    /**
     * Method to check if Tokens exist in database
     *
     * @param hashedToken  {@link String}
     * @return Boolean
     */
    public Boolean isRTPresent(String hashedToken) {
        try {
            UserSession userTokenDetails = userSessionRepo.findByHashedRT(hashedToken);
            if (userTokenDetails == null)
                return false;
            String hashedRT = userTokenDetails.getHashedRT();
            return hashedRT != null && hashedRT.equals(hashedToken);
        } catch (Exception e) {
            LOGGER.warn(AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG, REQUEST_UTIL, "isRTPresent", "while checking if tokens exist in database", e.getStackTrace());
            return false;
        }
    }

    /**
     * Method to validate a refresh token
     *
     * @param hashedToken {@link String}
     */
    public boolean validateRefreshToken(String hashedToken) {
        try {
            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            encryptor.setPassword(encryptorPassword);

            UserSession userTokenDetails = userSessionRepo.findByHashedRT(hashedToken);
            String encryptedRT = userTokenDetails.getEncryptedRT();
            String hashedRT = userTokenDetails.getHashedRT();

            if (encryptedRT == null)
                return false;
            String refreshToken1 = encryptor.decrypt(encryptedRT);
            String refreshToken2 = encryptor.decrypt(refreshToken1);
            uri = serviceUri(TOKEN_SERVICE, AuthConstants.GET_EXPIRATION_DATE);
            ResponseEntity<Date> expirationDateRTResponse = RestUtil.get(uri + refreshToken2, null, Date.class);
            if(expirationDateRTResponse == null){
                throw new RequestUtilException(INVALID_RT_TOKEN_EXCEPTION, HttpStatus.INTERNAL_SERVER_ERROR);
            }
            Date expirationDateRT = expirationDateRTResponse.getBody();
            if(expirationDateRT != null)
                return hashedToken.equals(hashedRT) && expirationDateRT.after(new Date(System.currentTimeMillis()));
            else
                return false;
        } catch (Exception e) {
            LOGGER.warn(AUTHENTICATION_SERVICE_WARN_EXCEPTION_LOG_TAG, REQUEST_UTIL, "validateRefreshToken", e.getMessage(), e.getStackTrace());
            return false;
        }
    }

    /**
     * Method to check if token is RefreshTokes or not.
     *
     * @param refreshToken  {@link String}
     * @return {@link Boolean}
     */
    public static Boolean isRefreshToken(String refreshToken) {
        boolean isRefresh;
        if (refreshToken.contains(".")) {
            String[] tokenSplit = refreshToken.split("\\.");
            String tokenSplitHeader = tokenSplit[0];
            byte[] decodedBytes = Base64.getDecoder().decode(tokenSplitHeader);
            String tokenHeader = new String(decodedBytes);
            isRefresh = tokenHeader.contains("alg");
        } else {
            isRefresh = true;
        }
        return isRefresh;
    }

    /**
     * Method to generate verification token.
     *
     * @param emailId  {@link String}
     * @param tokenDuration  {@link Long}
     * @return  {@link String}
     */
    public String verificationToken(String emailId, Long tokenDuration) {
        uri = serviceUri(TOKEN_SERVICE, AuthConstants.GENERATE_TOKEN);

        ResponseEntity<String> verificationTokenResponse = RestUtil.get(
                uri + String.valueOf(tokenDuration) + "/" + emailId,
                null, String.class);
        return verificationTokenResponse.getBody();
    }

    public String verificationOtpToken(AddRemoveMemberRequest addMemberRequest, Long tokenDuration) {
        uri = serviceUri(TOKEN_SERVICE, AuthConstants.GENERATE_TOKEN);

        ResponseEntity<String> verificationTokenResponse = RestUtil.post(
                uri + String.valueOf(tokenDuration) + "/" + addMemberRequest.getEmail(),
                null,addMemberRequest, String.class);
        return verificationTokenResponse.getBody();
    }
    /**
     * Method to generate MFA Secret
     *
     * @return  {@link String}
     */
    public String generateMFASecret() {
        uri = serviceUri(MFA_SERVICE, AuthConstants.GENERATE_MFA_SECRET);
        return RestUtil.get(String.valueOf(uri), null, String.class).getBody();
    }

    /**
     * Method to get userName from token
     *
     * @param verificationCode  {@link String}
     * @return  {@link String}
     */
    public String usernameFromToken(String verificationCode) {
        uri = serviceUri(TOKEN_SERVICE, AuthConstants.USERNAME);
        return RestUtil.get(uri + verificationCode, null, String.class).getBody();
    }

    /**
     * Method to generate Jwt Token
     *
     * @param userIdDetails  {@link String}
     * @param tokenType  {@link String}
     * @return  {@link String}
     */
    public String jwtToken(UserIdDetails userIdDetails, String tokenType) {
        uri = serviceUri(TOKEN_SERVICE, AuthConstants.GENERATE_TOKEN);
        return RestUtil.post(uri + tokenType, null, userIdDetails, String.class).getBody();
    }

    /**
     * Method to generate Jwt Token from UserProfile
     *
     * @param userProfile  {@link String}
     * @param tokenType  {@link String}
     * @return  {@link String}
     */
    public String jwtTokenFromUserProfile(UserProfile userProfile, String tokenType) {
        uri = serviceUri(TOKEN_SERVICE, AuthConstants.GENERATE_TOKEN);
        return RestUtil.post(uri + tokenType, null, userProfile, String.class).getBody();
    }

    /**
     * Method to get FetchResponse from token
     * @param emailId  {@link String}
     * @param requestDetails {@link FetchResponse}
     * @return  {@link String}
     */
    public String getFetchResponseToken(String emailId, FetchResponse requestDetails) {
        uri = serviceUri(TOKEN_SERVICE, AuthConstants.GENERATE_FETCH_RESPONSE_TOKEN);
        return webClientUtil.post(uri + "/" + emailId,null, requestDetails, String.class).getBody();
    }

    /**
     * Method to verify MFA verificationCode
     *
     * @param verificationCode  {@link String}
     * @param mfaSecret  {@link String}
     * @return  {@link String}
     */
    public ResponseEntity<Boolean> verifyFromMfaService(String verificationCode, String mfaSecret) {
        uri = serviceUri(MFA_SERVICE, AuthConstants.VERIFY_FROM_MFA_SERVICE);
        return RestUtil.post(
                uri + "/" + verificationCode + "/" + mfaSecret, null, null, Boolean.class);
    }


    /**
     * Method to get Email from token
     *
     * @param token  {@link String}
     * @return  {@link String}
     */
    public String getEmailFromToken(String token) {
        uri = serviceUri(TOKEN_SERVICE, AuthConstants.GET_EMAIL_FROM_TOKEN);
        return RestUtil.get(uri + token, null, String.class).getBody();
    }

    /**
     * Method to get Encoded token
     *
     * @param refreshToken  {@link String}
     * @return  {@link String}
     */
    public String hashedRefreshToken(String refreshToken) {
        uri = serviceUri(TOKEN_SERVICE, AuthConstants.GET_ENCODED_TOKEN);
        return RestUtil.get(uri + refreshToken, null, String.class).getBody();
    }

    /**
     * Method to get User mappings from token
     *
     * @param token  {@link String}
     * @return  {@link BaseResponse}
     */
    public BaseResponse getUserMappings(String token) {
        uri = serviceUri(TOKEN_SERVICE, AuthConstants.USER_MAPPINGS);
        return RestUtil.get(uri + token, null, BaseResponse.class).getBody();
    }

    /**
     * Method to generate internal token
     *
     * @param secretToken  {@link String}
     * @param userIdDetails  {@link UserIdDetails}
     * @return  {@link BaseResponse}
     */
    public BaseResponse getInternalToken(String secretToken, UserIdDetails userIdDetails) {
        uri = serviceUri(TOKEN_SERVICE, AuthConstants.GET_INTERNAL_TOKEN);
        return RestUtil.post(uri + "/"+ secretToken, null, userIdDetails, BaseResponse.class).getBody();
    }

    /**
     * Method to calculate Risk Score
     *
     * @param userId  {@link String}
     * @param fetchResponse  {@link FetchResponse}
     * @return  {@link ResponseEntity}
     */
    public ResponseEntity<RiskResponse> getRiskScore(String userId, FetchResponse fetchResponse) {
        uri = serviceUri(RBA_SERVICE, RBAConstants.RISK_SCORE);
        return webClientUtil
                .post(String.valueOf(uri) + "/" + userId, null, fetchResponse, RiskResponse.class);
    }

    /**
     * Method to save Authentication history
     *
     * @param userId  {@link String}
     * @param fetchResponse  {@link FetchResponse}
     * @return  {@link ResponseEntity}
     */
    public ResponseEntity<BaseResponse> saveAuthHistory(String userId, FetchResponse fetchResponse) {
        uri = serviceUri(RBA_SERVICE, RBAConstants.SAVE_AUTH_HISTORY);
        return webClientUtil
                .post(String.valueOf(uri) + "/" + userId, null, fetchResponse, BaseResponse.class);
    }

    /**
     * Method to delete Authentication history
     *
     * @param userId  {@link String}
     * @return  {@link ResponseEntity}
     */
    public ResponseEntity<BaseResponse> deleteAuthHistory(String userId) {
        uri = serviceUri(RBA_SERVICE, RBAConstants.DELETE_AUTH_HISTORY);
        return webClientUtil
                .delete(String.valueOf(uri) + "/" + userId, null, BaseResponse.class);
    }

    /**
     * Method to block Device
     *
     * @param userId  {@link String}
     * @param fetchResponse  {@link FetchResponse}
     * @return  {@link ResponseEntity}
     */
    public ResponseEntity<BaseResponse> blockDevice(String userId, FetchResponse fetchResponse) {
        uri = serviceUri(RBA_SERVICE, RBAConstants.BLOCK_DEVICE);
        return webClientUtil.post(String.valueOf(uri) + "/" + userId, null,
                fetchResponse, BaseResponse.class);
    }

    /**
     * Method to fetch blocked Device Status
     *
     * @param userId  {@link String}
     * @param ip  {@link String}
     * @return  {@link ResponseEntity}
     */
    public ResponseEntity<Boolean> getDeviceBlockStatus(String userId, String ip) {
        uri = serviceUri(RBA_SERVICE, RBAConstants.GET_BLOCK_STATUS);
        return webClientUtil.get(String.valueOf(uri) + "/" + userId + "/" + ip, null, Boolean.class);
    }

    /**
     * Method to unblock user Ips
     *
     * @param userId  {@link String}
     * @param fetchResponse  {@link FetchResponse}
     * @return  {@link ResponseEntity}
     */
    public ResponseEntity<BaseResponse> unblockUserIp(String userId, FetchResponse fetchResponse) {
        uri = serviceUri(RBA_SERVICE, RBAConstants.UNBLOCK_DEVICE);
        return webClientUtil.post(String.valueOf(uri) + "/" + userId, null, fetchResponse, BaseResponse.class);
    }

    /**
     * Method to fetch users BlockStatus
     *
     * @param userIds  {@link List}
     * @return  {@link BaseResponse}
     */
    public BaseResponse getUsersBlockStatus(List<String> userIds) {
        uri = serviceUri(RBA_SERVICE, RBAConstants.GET_USERS_BLOCK_STATUS);
        return webClientUtil.post(String.valueOf(uri), null, userIds, BaseResponse.class).getBody();
    }

    /**
     * Method to unblock user
     *
     * @param userId  {@link String}
     * @return  {@link BaseResponse}
     */
    public BaseResponse unblockUser(String userId) {
        uri = serviceUri(RBA_SERVICE, RBAConstants.UNBLOCK_USER);
        return webClientUtil.put(String.valueOf(uri) + "/" + userId, null, "null", BaseResponse.class).getBody();
    }

    /**
     * Method to fetch internal service uri
     *
     * @param serviceName {@link String}
     * @param resolveConst {@link String}
     * @return {@link URI}
     */
    private URI serviceUri(String serviceName, String resolveConst) {
        Optional<URI> discoveryUri=discoveryClient.getInstances(serviceName).stream().map(ServiceInstance::getUri).findFirst()
                .map(s -> s.resolve(resolveConst));

        if(discoveryUri.isEmpty()){
            LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,"Uri Not found.", REQUEST_UTIL, "serviceUri");
            throw new RequestUtilException(ACTION_FAILED.label, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return discoveryUri.get();
    }

    public BaseResponse getMappingsFromToken(String token) {
        uri = serviceUri(TOKEN_SERVICE, AuthConstants.GET_MAPPINGS_FROM_TOKEN);
        return RestUtil.get(uri + token, null, BaseResponse.class).getBody();
    }
}
