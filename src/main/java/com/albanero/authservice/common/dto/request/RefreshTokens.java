package com.albanero.authservice.common.dto.request;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

@Data
@Component
@ConfigurationProperties()
public class RefreshTokens {
	private String hashedRT;
	private String encryptedRT;
}
