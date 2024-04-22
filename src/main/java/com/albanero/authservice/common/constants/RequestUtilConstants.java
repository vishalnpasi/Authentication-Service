package com.albanero.authservice.common.constants;

/**
 * Interface that provide service name constants for
 * {@link com.albanero.authservice.common.util.RequestUtil}
 */
public final class RequestUtilConstants {
    public static final String RBA_SERVICE = "rba-service";
    public static final String TOKEN_SERVICE = "token-service";
    public static final String MFA_SERVICE="mfa-service";

    private RequestUtilConstants() {
        throw new IllegalStateException("RequestUtilConstants class");
    }

}
