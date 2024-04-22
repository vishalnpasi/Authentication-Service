package com.albanero.authservice.model;

import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

@Data
@Document(collection = "products")
public class Navigation {
	private Boolean required;
	private Panel panel;
}
