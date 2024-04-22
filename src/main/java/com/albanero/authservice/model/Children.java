package com.albanero.authservice.model;

import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

@Data
@Document(collection = "products")
public class Children {
	private String name;
	private String icon;
	private String id;
	private String route;
	private String hide;
}
