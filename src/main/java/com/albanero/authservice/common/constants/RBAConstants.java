package com.albanero.authservice.common.constants;

/**
 * Interface that provide RestController mapping constants for
 * {@link UserController}
 */
public final class RBAConstants {
	public static final String REQUEST_DETAILS = "/rba/api/request-details";
	public static final String RISK_SCORE = "/rba/api/risk-score";
	public static final String SAVE_AUTH_HISTORY = "/rba/api/save-auth-history";
	public static final String UPDATE_AUTH_HISTORY = "/rba/api/update-auth-history/";
	public static final String DELETE_AUTH_HISTORY = "/rba/api/delete-auth-history/";
	public static final String BLOCK_DEVICE = "/rba/api/block-device";
	public static final String GET_BLOCK_STATUS = "/rba/api/block-device-status";
	public static final String UNBLOCK_DEVICE = "/rba/api/unblock-device";
	public static final String GET_USERS_BLOCK_STATUS = "/rba/api/users/blocked-status";
	public static final String UNBLOCK_USER = "/rba/api/unblock-user";
	public static final String HIGH_RISK = "high";
	public static final String MODERATE_RISK = "moderate";
	public static final String LOW_RISK = "low";
	private RBAConstants() {
		throw new IllegalStateException("RBAConstants class");
	}
}
