package com.albanero.authservice.component;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.stereotype.Component;

import lombok.Data;

/**
 * Component class that holds all the properties defined and stored in the vault
 * 
 * @author arunima.mishra
 *
 */
@Data
@Component
@ConfigurationProperties()
@RefreshScope
public class Credentials {
	private String jotSecret;
	private String jasyptSecret;
	private String dbUser;
	private String dbPass;
	private String emailUser;
	private String emailPass;
}
