package com.albanero.authservice.common.constants;

/**
 * Interface that provides Token constants for Authenticate API
 * 
 */
public final class TokenConstants {
	public static final Long USER_VERIFICATION_TOKEN_DURATION = 3 * 24 * 60 * 60000l;
	public static final Long OTP_TOKEN_DURATION = 600000L;
	public static final Long APPROVE_EMAIL_TOKEN_DURATION  = 1 * 24 * 60 * 60000L;
	public static final Long ORG_PROJECT_MEMBER_INVITE_TOKEN_DURATION  = 3 * 60 * 60000L;	// 3 HOURS
	public static final Long NEW_PASSWORD_TOKEN_DURATION = 3600000L;
	public static final Long EXTERNAL_TOKEN_DURATION = 300000L;
	public static final String ACCESS = "access";
	public static final String REFRESH = "refresh";

	private TokenConstants() {
		throw new IllegalStateException("TokenConstants class");
	}
}
