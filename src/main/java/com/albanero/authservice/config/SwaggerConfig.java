package com.albanero.authservice.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;



@Configuration
public class SwaggerConfig {

	@Bean
	public OpenAPI iamServicesAPISpecs() {
		return new OpenAPI()
				.info(new Info().title("IAM Services APIs")
						.description("Identity and Access Management")
				);
	}

}
