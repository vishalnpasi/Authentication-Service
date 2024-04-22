package com.albanero.authservice.config;
import java.net.URI;

import com.albanero.authservice.exception.VaultConfigException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.vault.annotation.VaultPropertySource;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.config.AbstractVaultConfiguration;

import com.albanero.authservice.AuthenticationServiceApplication;
import com.albanero.authservice.common.constants.VaultConstants;

import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG;

/**
 * Loads the properties from cubbyhole/authentication-service with
 * {@link VaultPropertySource}.
 *
 * @see AuthenticationServiceApplication
 */
@Configuration
@VaultPropertySource(VaultConstants.VAULT_PATH)
public class VaultConfig extends AbstractVaultConfiguration {

	private static final Logger LOGGER = LoggerFactory.getLogger(VaultConfig.class);
	private static final String VAULT_CONFIG = "VaultConfig";

	/**
	 * Specify an endpoint for connecting to Vault.
	 */
	@Override
	public VaultEndpoint vaultEndpoint() {
		String uri = getEnvironment().getProperty("spring.cloud.vault.uri");
		if (uri != null) {
			return VaultEndpoint.from(URI.create(uri));
		}
		LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_WITH_MESSAGE_TAG,"Vault URL not found", VAULT_CONFIG, "vaultEndpoint");
		throw new VaultConfigException("Vault URL not found", HttpStatus.NOT_FOUND);
	}

	/**
	 * Configure a client authentication. Please consider a more secure
	 * authentication method for production use.
	 */
	@Override
	public ClientAuthentication clientAuthentication() {
		// ...
		String token = getEnvironment().getProperty("spring.cloud.vault.token");
		if (token != null) {
			return new TokenAuthentication(token);
		}
		// ...
		throw new IllegalStateException();
	}
}
