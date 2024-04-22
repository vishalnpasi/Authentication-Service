package com.albanero.authservice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.data.mongodb.config.EnableMongoAuditing;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.vault.annotation.VaultPropertySource;

import com.albanero.authservice.common.constants.VaultConstants;
import com.albanero.authservice.component.Credentials;


//@EnableEurekaClient

@SpringBootApplication
@EnableMongoAuditing
@EnableScheduling
@EnableConfigurationProperties(Credentials.class)
@VaultPropertySource(VaultConstants.VAULT_PATH)
@EnableDiscoveryClient
public class AuthenticationServiceApplication implements CommandLineRunner {

	private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationServiceApplication.class);

	private final Credentials credentials;

	public AuthenticationServiceApplication(Credentials credentials) {
		this.credentials = credentials;
	}

	public static void main(String[] args) {
		SpringApplication.run(AuthenticationServiceApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		LOGGER.info("-------------SECRETS FROM VAULT-------------");
		LOGGER.info("JWT SECRET FROM HASHICORP VAULT - {}", credentials.getEmailUser());


	}

}