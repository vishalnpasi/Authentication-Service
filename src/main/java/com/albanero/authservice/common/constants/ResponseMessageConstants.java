package com.albanero.authservice.common.constants;

public enum ResponseMessageConstants {

    VALID_TOKEN_GENERATED("Valid access token generated and returned."),
    VALID_API_ROLE_MAPPING("API-Role mapping is valid.");

    public final String label;

    ResponseMessageConstants(String label) {
        this.label = label;
    }

    @Override
    public String toString() {
        return this.label;
    }
}
