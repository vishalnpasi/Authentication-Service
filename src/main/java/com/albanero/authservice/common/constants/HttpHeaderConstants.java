package com.albanero.authservice.common.constants;

public final class HttpHeaderConstants {
	public static final String X_ORG_ID = "x-org-id";
	public static final String X_PROJECT_ID = "x-project-id";
	public static final String X_ORG_LEVEL = "x-org-level";
	public static final String X_SECRET = "x-secret";

	private HttpHeaderConstants() {
		throw new IllegalStateException("HttpHeaderConstants class");
	}
}
