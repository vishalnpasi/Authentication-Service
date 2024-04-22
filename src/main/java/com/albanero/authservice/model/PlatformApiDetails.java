package com.albanero.authservice.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

import jakarta.validation.constraints.NotBlank;

@Data
@Document(collection = "platformApiDetails")
public class PlatformApiDetails {
	@Id
	private String id;
	@NotBlank
	private String apiRoute;
	@NotBlank
	private String apiMethod;
	@NotBlank
	private String apiDescription;
}
