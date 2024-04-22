package com.albanero.authservice.config;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Set;

@Configuration
public class CorsConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(CorsConfig.class);

    private static final String ALBANERO_IO = "albanero.io";

    private static final Set<String> CORS_ALLOW_DEFAULT = Set.of(
            "https://demo.albanero.io",
            "https://api.demo.albanero.io",
            "https://dev1.albanero.io",
            "https://api.dev1.albanero.io",
            "https://dev2.albanero.io",
            "https://api.dev2.albanero.io",
            "https://projects.albanero.io",
            "https://api.projects.albanero.io",
            "https://qa.albanero.io",
            "https://api.qa.albanero.io"
    );
    @Value("${cors.allow:}")
    private String corsAllowString;

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            final String[] corsAllow = getCorsAllowedAddresses().toArray(new String[0]);
            @Override
            public void addCorsMappings(@NonNull CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins(corsAllow)
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
                        .allowedHeaders("*")
                        .allowCredentials(true)
                        .maxAge(3600);
            }
        };
    }

    public Set<String> getCorsAllowedAddresses() {
        if (StringUtils.hasLength(corsAllowString)) {
            return Set.of(corsAllowString.split(","));
        }
        return CORS_ALLOW_DEFAULT;
    }

    public boolean isOriginAllowed(String origin) {
        if (StringUtils.hasLength(origin)) {
            if(isSecureAlbaneroAddress(origin)) {
                return true;
            }
            LOGGER.info("Allowed addresses: {}", getCorsAllowedAddresses());
            return getCorsAllowedAddresses().contains(origin);
        }
        return false;
    }

    private static boolean isSecureAlbaneroAddress(String origin) {
        return origin.startsWith("https") && origin.endsWith(ALBANERO_IO);
    }
}
