package com.albanero.authservice.filter;

import java.io.IOException;

import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;


@Component
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
						 AuthenticationException authException) throws IOException {
		log.error("Auth exception occurred: {}", authException.getMessage(), authException);
		String message;
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		if (authException.getCause() != null) {
			message = authException.getCause().toString() + " " + authException.getMessage();
		} else {
			message = authException.getMessage();
		}
		if (Objects.equals(authException.getClass().getName(),
				"org.springframework.security.authentication.InsufficientAuthenticationException")) {
			message = "Invalid Token";
		}

		response.getOutputStream().println("{\n" +
				"  \"message\": \"" + message + "\",\n" +
				"  \"success\": false,\n" +
				"  \"statusCode\": \"401\"\n" +
				"}");
	}
}