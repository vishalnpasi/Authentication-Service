package com.albanero.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.reactive.function.client.WebClient;

@SuppressWarnings("deprecation")
@Configuration
@EnableWebSecurity
public class WebClientConfig {


	@Bean
	public WebClient.Builder getWebClientBuilder() {
		return WebClient.builder();

	}

	
}
