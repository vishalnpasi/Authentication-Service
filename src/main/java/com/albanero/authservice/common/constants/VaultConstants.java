package com.albanero.authservice.common.constants;

/**
 * Interface that provide RestController mapping constants
 */
public final class VaultConstants {
    private VaultConstants() {
        throw new IllegalStateException("VaultConstants class");
    }
    public static final String VAULT_PATH = "secret/authentication-service";
}
